Pod::Spec.new do |s|
  s.name             = 'schat_cert_pinning'
  s.version          = '0.1.0'
  s.summary          = 'Chain-walking SPKI cert pinning for KalkiChat mobile apps.'
  s.homepage         = 'https://github.com/mahakaal02/KalkiChat'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'KalkiChat' => 'eng@kalkichat.example' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.platform         = :ios, '12.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version    = '5.0'
end
