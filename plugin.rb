# frozen_string_literal: true

# name: discourse-content-redirector
# about: Provides /content?u=... which decodes urlsafe-base64 and redirects.
# version: 0.2
# authors: you

after_initialize do
  require "base64"
  require "uri"

  module ::ContentRedirector
    ENABLED = true

    # Optional: prevent crazy-long payloads
    MAX_PARAM_LEN = 4096

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
  end

  class ::ContentRedirector::Engine < ::Rails::Engine
    engine_name "content_redirector"
    isolate_namespace ContentRedirector
  end

  class ::ContentRedirector::ContentController < ::ActionController::Base
    protect_from_forgery with: :null_session

    def content
      return render(plain: "disabled", status: 404) unless ::ContentRedirector::ENABLED

      url = ::ContentRedirector.decode_urlsafe_base64(params[:u])
      return render(plain: "missing/invalid", status: 400) if url.blank?

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

      redirect_to url, allow_other_host: true, status: 302
    rescue => e
      Rails.logger.warn("[discourse-content-redirector] controller error: #{e.class}: #{e.message}")
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
