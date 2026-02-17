# frozen_string_literal: true

# name: discourse-content-redirector
# about: Provides /content?u=... which decodes urlsafe-base64 and redirects.
# version: 0.1
# authors: you

after_initialize do
  require "base64"

  module ::ContentRedirector
    def self.decode_urlsafe_base64(s)
      return nil if s.blank?
      str = s.to_s.strip.tr("-_", "+/")

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

  class ::ContentRedirectorController < ::ApplicationController
    skip_before_action :check_xhr
    skip_before_action :preload_json

    def content
      url = ::ContentRedirector.decode_urlsafe_base64(params[:u])

      return render(plain: "missing/invalid", status: 400) if url.blank?

      begin
        uri = URI.parse(url)
        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          return render plain: "invalid url", status: 400
        end
      rescue
        return render plain: "invalid url", status: 400
      end

      redirect_to url, allow_other_host: true, status: 302
    end
  end

  Discourse::Application.routes.append do
    get "/content" => "content_redirector#content"
  end
end
