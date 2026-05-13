# frozen_string_literal: true

module Decidim
  module Adminauth
    module Devise
      module OtpRoutesHelper
        # Fixes an issue that the routes are fetched from the adminauth engine
        # instead of the core engine that has the OTP credential routes mounted.
        # Without this, the OTP credentials view would break at the layout level
        # due to the missing route.
        def _routes
          decidim.routes
        end
      end
    end
  end
end
