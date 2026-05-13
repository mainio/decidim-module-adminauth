# frozen_string_literal: true

module Decidim
  module Adminauth
    class OtpTokenMailer < Decidim::ApplicationMailer
      include Decidim::TranslationsHelper
      include Decidim::SanitizeHelper

      helper Decidim::TranslationsHelper

      # Send an email to an user with the OTP login token.
      #
      # user - the user to send the OTP token to
      # token - the OTP token (code)
      def otp_token(user, token)
        with_user(user) do
          @organization = user.organization
          @service_name = translated_attribute(@organization.name)
          @user = user
          @token = token

          subject = I18n.t(
            "otp_token.subject",
            scope: "decidim.adminauth.otp_token_mailer",
            service_name: @service_name
          )
          mail(to: user.email, subject: subject)
        end
      end
    end
  end
end
