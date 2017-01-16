# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "graphene/version"

Gem::Specification.new do |s|
  s.name        = "graphene-ruby"
  s.version     = Graphene::VERSION
  s.authors     = ["Alex Chien"]
  s.email       = ["alexchien97@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{graphene utils and protocol in ruby}
  s.description = %q{This is a ruby library for interacting with the graphene protocol/network}
  s.homepage    = "https://github.com/AlexChien/graphene-ruby"

  s.rubyforge_project = "graphene-ruby"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.required_rubygems_version = ">= 1.3.6"
end
