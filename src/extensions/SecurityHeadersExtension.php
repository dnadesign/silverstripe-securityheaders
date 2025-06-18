<?php

namespace DNADesign\SecurityHeaders;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Environment;

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
            if (!Director::isDev() || Config::inst()->get(SecurityHeadersExtension::class, 'force_headers_in_dev')) {
                $headersToSend = (array) Config::inst()->get(SecurityHeadersExtension::class, 'headers');
                $whitelist = (array) Config::inst()->get(SecurityHeadersExtension::class, 'whitelist');
                $whitelist = $this->processEnvironmentVariables($whitelist);
                $whitelistValue = null;

                if ($whitelist) {
                    $whitelistValue = $this->getSources($whitelist);
                }

                foreach ($headersToSend as $header => $value) {
                    if ($header === 'Content-Security-Policy') {
                        $supportedBrowser = $this->browserHasWorkingCSPImplementation();
                        if (!$supportedBrowser && ($value === '' || $value === false)) {
                            continue;
                        }

                        if ($whitelistValue) {
                            $response->addHeader($header, $whitelistValue);
                        }
                    } else {
                        $response->addHeader($header, $value);
                    }
                }
            }
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

    private function getSources($whitelist)
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

        return trim($sources);
    }

    /**
     * Process environment variables in the whitelist configuration
     * Replaces backtick-wrapped environment variable names with their values
     * @param array $whitelist
     * @return array
     */
    private function processEnvironmentVariables($whitelist)
    {
        foreach ($whitelist as $directive => $config) {
            if (isset($config['data']) && is_array($config['data'])) {
                foreach ($config['data'] as $index => $value) {
                    // Check if the value is wrapped in backticks (environment variable syntax)
                    if (is_string($value) && preg_match('/^`([^`]+)`$/', $value, $matches)) {
                        $envVar = $matches[1];
                        $envValue = Environment::getEnv($envVar);
                        
                        if ($envValue !== false && $envValue !== null) {
                            $whitelist[$directive]['data'][$index] = $envValue;
                        } else {
                            // Remove the invalid environment variable from the array
                            unset($whitelist[$directive]['data'][$index]);
                        }
                    }
                }
                // Re-index the array after potential unset operations
                $whitelist[$directive]['data'] = array_values($whitelist[$directive]['data']);
            }
        }
        return $whitelist;
    }    
}