require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'
require 'bundler'

Bundler::GemHelper.install_tasks

desc 'Default: run prowler unit tests.'
task :default => :test

desc 'Test the prowler gem.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the prowler gem.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'Prowler'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('lib/**/*.rb')
end
