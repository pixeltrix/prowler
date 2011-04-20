# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "prowler/version"

Gem::Specification.new do |s|
  s.name        = "prowler"
  s.version     = Prowler::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Andrew White"]
  s.email       = ["andyw@pixeltrix.co.uk"]
  s.homepage    = %q{http://github.com/pixeltrix/prowler/}
  s.summary     = %q{Provides access to the Prowl API (http://prowlapp.com).}
  s.description = <<-EOF
A plugin/gem that provides access to the Prowl API (http://prowlapp.com).
Works with Rails 2 or 3 as well as any other Ruby web frameworks or in
your own scripts.
EOF

  s.files = [
    ".gemtest",
    "CHANGELOG",
    "MIT-LICENSE",
    "README.md",
    "Rakefile",
    "VERSION",
    "init.rb",
    "install.rb",
    "lib/prowler.rb",
    "lib/prowler/application.rb",
    "lib/prowler/configuration.rb",
    "lib/prowler/delayed_job.rb",
    "lib/prowler/priority.rb",
    "lib/prowler/railtie.rb",
    "lib/prowler/response.rb",
    "lib/prowler/tasks.rb",
    "lib/prowler/version.rb",
    "prowler.gemspec",
    "tasks/prowler.rake",
    "test/config/cacert.pem",
    "test/prowler_test.rb"
  ]

  s.test_files    = ["test/prowler_test.rb"]
  s.require_paths = ["lib"]

  s.add_development_dependency "bundler", "~> 1.0.10"
  s.add_development_dependency "mocha", "~> 0.9.12"
  s.add_development_dependency "shoulda", "~> 2.11.3"
  s.add_development_dependency "webmock", "~> 1.6.2"

end

