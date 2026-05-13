# frozen_string_literal: true

require "devise"

module Devise
  mattr_accessor :otp_authentication_timeout
  self.otp_authentication_timeout = 5.minutes

  mattr_accessor :otp_issuer
  self.otp_issuer = Rails.application.class.module_parent_name

  mattr_accessor :otp_maximum_attempts
  self.otp_maximum_attempts = 10

  mattr_accessor :otp_token_resend_interval
  self.otp_token_resend_interval = 1.minute
end

Devise.add_module(
  :otp_authenticatable,
  controller: :tokens,
  model: "devise/models/otp_authenticatable",
  route: :otp,
  strategy: true
)
