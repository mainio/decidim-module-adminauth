# Decidim::Adminauth

[![Build Status](https://github.com/mainio/decidim-module-adminauth/actions/workflows/ci_adminauth.yml/badge.svg)](https://github.com/mainio/decidim-module-adminauth/actions)
[![codecov](https://codecov.io/gh/mainio/decidim-module-adminauth/branch/main/graph/badge.svg)](https://codecov.io/gh/mainio/decidim-module-adminauth)

Hardened admin access for Decidim. Adds one time login codes requirement for
admins to make admin access more restricted. The login codes are delivered by
email to the user during their login attempts.

The gem has been developed by [Mainio Tech](https://www.mainiotech.fi/).

The authentication logic is highly based on the MIT licensed
[devise-otp gem](https://github.com/wmlele/devise-otp). This gem integrates more
deeply with Decidim and narrows down the scope of the OTP logins for admins
only. The OTP code is also delivered by email instead of an authentication
application for ease of use and introduction.

The development has been sponsored by the
[City of Helsinki](https://www.hel.fi/).

## Installation

Add this line to your application's Gemfile:

```ruby
gem "decidim-adminauth", github: "mainio/decidim-module-adminauth"
```

And then execute:

```bash
$ bundle
$ bundle exec rails decidim_adminauth:install:migrations
$ bundle exec rails db:migrate
```

## Usage

After installing this gem, the features provided by this gem are automatically
enabled.

Admins are required to enter a login code sent to their email addresses in order
to harden the admin access for the platform. This way if passwords are leaked,
there is a secondary step required for the attackers to gain access to the
target user's email address.

## Contributing

See [Decidim](https://github.com/decidim/decidim).

### Testing

To run the tests run the following in the gem development path:

```bash
$ bundle
$ DATABASE_USERNAME=<username> DATABASE_PASSWORD=<password> bundle exec rake test_app
$ DATABASE_USERNAME=<username> DATABASE_PASSWORD=<password> bundle exec rspec
```

Note that the database user has to have rights to create and drop a database in
order to create the dummy test app database.

In case you are using [rbenv](https://github.com/rbenv/rbenv) and have the
[rbenv-vars](https://github.com/rbenv/rbenv-vars) plugin installed for it, you
can add these environment variables to the root directory of the project in a
file named `.rbenv-vars`. In this case, you can omit defining these in the
commands shown above.

### Test code coverage

If you want to generate the code coverage report for the tests, you can use
the `SIMPLECOV=1` environment variable in the rspec command as follows:

```bash
$ SIMPLECOV=1 bundle exec rspec
```

This will generate a folder named `coverage` in the project root which contains
the code coverage report.

### Localization

Currently localization of the module happens in this repository only.

## License

See [LICENSE-AGPLv3.txt](LICENSE-AGPLv3.txt).
