# frozen_string_literal: true

$LOAD_PATH.push File.expand_path("lib", __dir__)

require "decidim/adminauth/version"

Gem::Specification.new do |s|
  s.name = "decidim-adminauth"
  s.version = Decidim::Adminauth.version
  s.authors = ["Antti Hukkanen"]
  s.email = ["antti.hukkanen@mainiotech.fi"]
  s.required_ruby_version = "~> 3.0"
  s.metadata = { "rubygems_mfa_required" => "true" }

  s.summary = "A decidim module to improve admin authentication."
  s.description = "Hardened admin access for Decidim."
  s.homepage = "https://github.com/decidim/decidim-module-adminauth"
  s.license = "AGPL-3.0"

  s.files = Dir[
    "{app,config,db,lib}/**/*",
    "LICENSE-AGPLv3.txt",
    "Rakefile",
    "README.md"
  ]

  s.add_dependency "decidim-core", Decidim::Adminauth.decidim_version
  s.add_dependency "rotp", "~> 6.3"
end
