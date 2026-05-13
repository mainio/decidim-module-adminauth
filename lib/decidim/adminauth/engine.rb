# frozen_string_literal: true

require "rails"
require "decidim/core"

module Decidim
  module Adminauth
    # This is the engine that runs on the public interface of adminauth.
    class Engine < ::Rails::Engine
      isolate_namespace Decidim::Adminauth

      initializer "decidim_adminauth.add_customizations", before: :add_routing_paths do |app|
        config.to_prepare do
          # models
          ::Decidim::User.include(UserExtensions)
        end

        # The following hook is for the development environment and it is needed
        # to load the correct Devise configurations to the Decidim::User model
        # BEFORE the routes are reloaded in Decidim::Core::Engine. Without this,
        # the extra Devise modules are lost during application reloads as the
        # Decidim::User class is reloaded during which the Devise configurations
        # are overridden by the core class. After the override, the routes are
        # reloaded (before call to to_prepare) which causes the extra Devise
        # modules to get lost.
        #
        # The load order is:
        # - Models, including Decidim::Core::Engine models (sets the Devise
        #   configuration back to Decidim defaults)
        # - ActionDispatch::Reloader - after_class_unload hook (below)
        # - Routes, including Decidim::Core::Engine routes (reloads the routes
        #   using the Devise configuration set by Decidim::Core)
        # - to_prepare hook (which would be the normal place for this but too
        #   late in the code reloading process)
        #
        # In case you are planning to change this, make sure that the following
        # works:
        # - Load the login page and login as OTP enabled user (admin)
        # - When you see the OTP credentials page, make a change to any file
        #   under the `app` or `config/locales` folders
        # - Reload the OTP credentials page and see that it renders correctly
        #
        # NOTE: This problem only occurs when the models and routes are
        #       reloaded, i.e. in development environment.
        app.reloader.after_class_unload do
          ::Decidim::User.include(UserExtensions)
        end
      end
    end
  end
end
