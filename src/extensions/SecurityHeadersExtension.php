<?php

namespace DNADesign\SecurityHeaders;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Extension;

/**
 * This is a copy of the SecurityHeaderControllerExtension from security headers
 * Used to override the setting of Content-Security-Policy
 * Class SecurityHeaderControllerExtension
 * @package App\SilverStripe
 */

class SecurityHeadersExtension extends Extension
{
  public function onAfterInit()
  {
    $response = $this->owner->getResponse();
    $exceptions = (array) Config::inst()->get(SecurityHeadersExtension::class, 'exceptions');

    if (!in_array($this->owner->data(), $exceptions)) {
      if (!Director::isDev()) {
        $headersToSend = (array) Config::inst()->get(SecurityHeadersExtension::class, 'headers');
        $xHeaderMap = (array) Config::inst()->get(SecurityHeadersExtension::class, 'x_headers_map');
        $whitelist = (array) Config::inst()->get(SecurityHeadersExtension::class, 'whitelist');
        $whitelistValue = null;

        if ($whitelist) {
          $whitelistValue = $this->getSources($whitelist);
        }

        foreach ($headersToSend as $header => $value) {
          $suporttedBrowser = $this->browserHasWorkingCSPImplementation();

          if ($header === 'Content-Security-Policy' && !$suporttedBrowser && ($value === '' || $value === false)) {
            continue;
          }

          if ($header === 'Content-Security-Policy') {
            if ($whitelistValue) {
              $response->addHeader($header, $whitelistValue);
            }
          } else {
            $response->addHeader($header, $value);
          }

          if (isset($xHeaderMap[$header])) {
            foreach ($xHeaderMap[$header] as $xHeader) {
              if ($header === 'Content-Security-Policy') {
                if ($whitelistValue) {
                  $response->addHeader($xHeader, $whitelistValue);
                }
              } else {
                $response->addHeader($xHeader, $value);
              }
            }
          }
        }
      }

      $response->removeHeader('X-Content-Security-Policy'); // this causes issues in some browsers
    }
  }

  private function browserHasWorkingCSPImplementation()
  {
    $agent = $this->owner->getRequest()->getHeader('User-Agent') ?? '';
    $agent = strtolower($agent);

    if (strpos($agent, 'safari') === false) {
      return true;
    }

    $split = explode('version/', $agent);

    if (!isset($split[1])) {
      return true;
    }

    $version = trim($split[1]);
    $versions = explode('.', $version);

    if (isset($versions[0]) && $versions[0] <= 5) {
      return false;
    }

    return true;
  }

  private static function getSources($whitelist)
  {
    $sources = '';

    foreach (array_keys($whitelist) as $value) {
      $sources .= $value . ' ';

      foreach (array_keys($whitelist[$value]) as $innerValue) {
        $value = $whitelist[$value][$innerValue];
        if (!empty($value)) {
          $sources .= implode(' ', $value);
        }
      }

      $sources .= '; ';
    }

    return $sources;
  }
}
