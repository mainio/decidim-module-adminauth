# frozen_string_literal: true

module ActionDispatch::Routing
  # Based on the devise-otp gem (MIT).
  class Mapper
    protected

    def devise_otp(mapping, controllers)
      namespace :otp, module: :"decidim/adminauth" do
        resource :credential, only: [:show, :create, :update], path: mapping.path_names[:credentials], controller: controllers[:otp_credentials]
      end
    end
  end
end
