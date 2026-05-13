# frozen_string_literal: true

module Decidim
  module Adminauth
    module UserExtensions
      extend ActiveSupport::Concern

      included do
        devise :otp_authenticatable
      end
    end
  end
end
