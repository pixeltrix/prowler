require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the prowler plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the prowler plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'Prowler'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "prowler"
    gemspec.summary = "Provides access to the Prowl API (http://prowlapp.com)."
    gemspec.email = "andyw@pixeltrix.co.uk"
    gemspec.homepage = "http://github.com/pixeltrix/prowler/"
    gemspec.description = "A plugin/gem that provides access to the Prowl API (http://prowlapp.com). Works with Rails 2 or 3 as well as any other Ruby web frameworks or in your own scripts."
    gemspec.authors = ["Andrew White"]
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end
