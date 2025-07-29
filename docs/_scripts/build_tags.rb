#!/usr/bin/env ruby
require "fileutils"
require "yaml"
require "date"                             

SITE_DIR = Dir.pwd
TAGS_DIR = File.join(SITE_DIR, "tags")

FileUtils.rm_rf(TAGS_DIR)
FileUtils.mkdir_p(TAGS_DIR)

posts = Dir.glob("_posts/**/*.{md,markdown}").map do |path|
  fm   = File.read(path).split(/^---\s*$|^\.\.\.\s*$/)[1] || ""
  data = YAML.safe_load(
           fm,
           permitted_classes: [Time, Date],  
           aliases: true
         ) || {}
  { path: path, tags: Array(data["tags"]).map(&:to_s) }
end

tag_index = Hash.new { |h, k| h[k] = [] }
posts.each { |post| post[:tags].each { |t| tag_index[t] << post } }

def slugify(str)
  str.strip.downcase.gsub(/\s+/, "-")
end

tag_index.each_key do |tag|
  slug = slugify(tag)
  FileUtils.mkdir_p(File.join(TAGS_DIR, slug))
  File.write(
    File.join(TAGS_DIR, slug, "index.md"),
    <<~MD
      ---
      layout: tag
      tag: #{tag}              # <‑‑ keep the original capitalization!
      permalink: /tags/#{slug}/
      ---
    MD
  )
end

puts "Generated #{tag_index.size} tag pages in /tags/ 🎉"
