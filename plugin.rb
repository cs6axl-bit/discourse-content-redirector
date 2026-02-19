# frozen_string_literal: true

# name: discourse-content-redirector
# about: Provides /content?u=... which decodes urlsafe-base64 and redirects. Optional external logging to a PHP endpoint.
# version: 0.3.1
# authors: you

enabled_site_setting :content_redirector_enabled

after_initialize do
  require "base64"
  require "uri"
  require "net/http"
  require "json"
  require "securerandom"
  require "time"

  module ::ContentRedirector
    PLUGIN_NAME = "discourse-content-redirector"

    # Optional: prevent crazy-long payloads
    MAX_PARAM_LEN = 4096

    # Only these params are extracted from destination URL querystring:
    # NEW: aff_sub1/aff_sub2
    # Still supports sub_aff1/sub_aff2 as backward-compat mapping (optional)
    EXTRACT_KEYS = %w[aff_sub1 aff_sub2 subid subid2 sub_aff1 sub_aff2].freeze

    def self.decode_urlsafe_base64(s)
      return nil if s.blank?

      raw = s.to_s.strip
      return nil if raw.length > MAX_PARAM_LEN

      str = raw.tr("-_", "+/")

      # add padding
      pad = (4 - (str.length % 4)) % 4
      str = str + ("=" * pad)

      decoded = Base64.decode64(str)
      decoded.force_encoding("UTF-8")
      return nil unless decoded.valid_encoding?

      decoded
    rescue
      nil
    end

    def self.external_log_enabled?
      SiteSetting.content_redirector_external_log_enabled &&
        SiteSetting.content_redirector_external_log_endpoint.present?
    rescue
      false
    end

    def self.external_log_endpoint
      SiteSetting.content_redirector_external_log_endpoint.to_s
    rescue
      ""
    end

    def self.external_log_timeout_ms
      v = SiteSetting.content_redirector_external_log_timeout_ms.to_i
      v = 1500 if v <= 0
      v
    rescue
      1500
    end

    def self.extract_tracking_params(uri)
      out = {}
      return out if uri.nil? || uri.query.blank?

      parsed = Rack::Utils.parse_nested_query(uri.query) rescue {}

      EXTRACT_KEYS.each do |k|
        v = parsed[k]
        out[k] = v.to_s if v.present?
      end

      # Backward-compat: if old params exist but new ones don't, map them
      if out["aff_sub1"].blank? && out["sub_aff1"].present?
        out["aff_sub1"] = out["sub_aff1"]
      end
      if out["aff_sub2"].blank? && out["sub_aff2"].present?
        out["aff_sub2"] = out["sub_aff2"]
      end

      out
    end
  end

  class ::ContentRedirector::Engine < ::Rails::Engine
    engine_name "content_redirector"
    isolate_namespace ContentRedirector
  end

  # ---------------------------
  # Background job: POST log JSON to external endpoint
  # ---------------------------
  module ::Jobs
    class ContentRedirectorExternalLog < ::Jobs::Base
      def execute(args)
        payload = args["payload"] || {}
        endpoint = ::ContentRedirector.external_log_endpoint
        return if endpoint.blank?

        uri = URI.parse(endpoint)
        return unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")

        timeout_s = (::ContentRedirector.external_log_timeout_ms.to_f / 1000.0)
        http.open_timeout = timeout_s
        http.read_timeout = timeout_s

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(payload)

        http.request(req)
      rescue => e
        Rails.logger.warn("[#{::ContentRedirector::PLUGIN_NAME}] external log failed: #{e.class}: #{e.message}")
      end
    end
  end

  class ::ContentRedirector::ContentController < ::ActionController::Base
    protect_from_forgery with: :null_session

    def content
      return render(plain: "disabled", status: 404) unless SiteSetting.content_redirector_enabled

      url = ::ContentRedirector.decode_urlsafe_base64(params[:u])
      return render(plain: "missing/invalid", status: 400) if url.blank?

      uri = nil
      begin
        uri = URI.parse(url)

        # Only http(s)
        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          return render(plain: "invalid url", status: 400)
        end

        # Basic sanity
        return render(plain: "invalid url", status: 400) if uri.host.blank?
      rescue
        return render(plain: "invalid url", status: 400)
      end

      # Optional: reduce caching of redirects
      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "0"

      # ---------------------------
      # Optional external logging
      # ---------------------------
      if ::ContentRedirector.external_log_enabled?
        extracted = ::ContentRedirector.extract_tracking_params(uri)

        # best-effort client IPs
        xff = request.headers["X-Forwarded-For"].to_s
        real_ip = request.headers["X-Real-IP"].to_s

        payload = {
          event: "content_redirect",
          at_utc: Time.now.utc.iso8601,
          request_id: (request.request_id rescue SecureRandom.hex(12)),
          dest_url: url,

          # extracted affiliate params from DESTINATION url
          aff_sub1: extracted["aff_sub1"],
          aff_sub2: extracted["aff_sub2"],
          subid:    extracted["subid"],
          subid2:   extracted["subid2"],

          # client data
          ip: (request.remote_ip rescue nil),
          x_forwarded_for: (xff.present? ? xff : nil),
          x_real_ip: (real_ip.present? ? real_ip : nil),
          user_agent: (request.user_agent.to_s.presence)
        }.compact

        Jobs.enqueue(:content_redirector_external_log, payload: payload)
      end

      redirect_to url, allow_other_host: true, status: 302
    rescue => e
      Rails.logger.warn("[#{::ContentRedirector::PLUGIN_NAME}] controller error: #{e.class}: #{e.message}")
      render(plain: "error", status: 500)
    end

    def options
      response.status = 204
      self.response_body = ""
    end
  end

  # ---------------------------
  # Routes (inside engine)
  # ---------------------------
  ContentRedirector::Engine.routes.draw do
    get     "/" => "content#content"
    options "/" => "content#options"
  end

  # ---------------------------
  # Mount at /content
  # ---------------------------
  Discourse::Application.routes.append do
    mount ::ContentRedirector::Engine, at: "/content"
  end
end
