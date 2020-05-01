# Silverstripe Security Headers Extension

Security headers module for Silverstripe v4.
Enable setting of content security policy (CSP).

## Setting CSP rules

You should set your own rules in your yml file. Below is just a basic usages example.

The basic usage

```yml
DNADesign\SecurityHeaders\SecurityHeadersExtension:
# Add exceptions per page type - Optional
  exceptions:
    - PageType
  headers:
    - ...
  x_headers_map:
    - ...
  whitelist:
    - ...
```

Add the adequate rules in your local _config/.yml file

```yml
# CSP extended e.g
DNADesign\SecurityHeaders\SecurityHeadersExtension:
  headers:
    Strict-Transport-Security: 'max-age=31536000; includeSubDomains'
    X-Frame-Options: 'SAMEORIGIN'
    Access-Control-Allow-Origin: 'self'
    X-Content-Type-Options: nosniff
    x-xss-protection: 1; mode=block
    Referrer-Policy: strict-origin-when-cross-origin
    Content-Security-Policy: whitelist
  x_headers_map:
    Content-Security-Policy:
      - X-Content-Security-Policy
      - X-WebKit-CSP
    Frame-Options:
      - X-Frame-Options
  whitelist:
    default-src:
      data:
        - '''none'''
    script-src:
      data:
        - '''self'''
        - '''unsafe-inline'''
        - '''unsafe-eval'''
    style-src:
      data:
        - '''self'''
        - '''unsafe-inline'''
    font-src:
      data:
        - '''self'''
    img-src:
      data:
        - '''self'''
        - 'data:'
        - 'https://www.google.com'
    form-action:
      data:
        - '''self'''
    manifest-src:
      data:
        - '''self'''
    frame-src:
      data:
        - 'https://www.google.com'
    frame-ancestors:
      data:
        - '''self'''
    connect-src:
      data:
        - '''self'''
        - 'https://www.google.com'
    base-uri:
      data:
        - '''self'''
```

## Testing

You can test your CSP rules with [CSP Evaluator](https://chrome.google.com/webstore/detail/csp-evaluator/fjohamlofnakbnbfjkohkbdigoodcejf) and [Caspr:Enforcer](https://chrome.google.com/webstore/detail/caspr-enforcer/fekcdjkhlbjngkimekikebfegbijjafd)

## References
This module was based on [guttmann/silverstripe-security-headers](https://github.com/guttmann/silverstripe-security-headers)

[CSP docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## Disclaimer

I am not a security expert - there are no default header rules used in this module, you should do your on research and see if anything from the above example fits your needs.

Please send me a pull request for any issues you spot or improvements that can be made.