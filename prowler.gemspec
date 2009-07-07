Gem::Specification.new do |s|
  s.platform    = Gem::Platform::RUBY
  s.name        = 'prowler'
  s.version     = "1.0.0"
  s.summary     = 'Provides access to the Prowl API.'
  s.description = <<-EOF
    A simple wrapper class that provides basic access to the Prowl API.
  EOF
  s.author      = 'Andrew White'
  s.email       = 'andyw@pixeltrix.co.uk'
  s.homepage    = 'http://github.com/pixeltrix/prowler/'
  s.has_rdoc    = true

  s.requirements << 'none'
  s.require_path = 'lib'

  s.files = [
      'prowler.gemspec',
      'INSTALL',
      'install.rb',
      'lib/prowler.rb',
      'MIT-LICENSE',
      'Rakefile',
      'README',
      'tasks/prowler.rake',
      'test/prowler_test.rb',
    ]

  s.test_file = 'test/prowler_test.rb'
end
