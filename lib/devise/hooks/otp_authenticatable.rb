# frozen_string_literal: true

# After each sign in, clear the OTP session details. This is only triggered when
# the user is explicitly set (with set_user).
Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  record.clear_otp_session! if record.respond_to?(:clear_otp_session!) && warden.authenticated?(options[:scope])
end
