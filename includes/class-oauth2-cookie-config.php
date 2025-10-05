<?php
/**
 * OAuth2 Cookie Configuration Class
 *
 * Wrapper for WP REST Auth Toolkit's CookieConfig class.
 * Provides environment-aware cookie configuration for OAuth2 refresh tokens.
 * Automatically adjusts cookie security settings based on environment (development/production)
 * with optional manual overrides via constants or filters.
 *
 * This is a backwards-compatible wrapper around the shared CookieConfig implementation
 * from wp-rest-auth-toolkit package.
 *
 * @package   WPRESTAuthOAuth2
 * @author    WordPress Developer
 * @copyright 2025 WordPress Developer
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WPRestAuth\AuthToolkit\Http\CookieConfig;

/**
 * OAuth2 Cookie Configuration Class.
 *
 * Wrapper for the shared CookieConfig implementation from wp-rest-auth-toolkit.
 * Manages cookie security settings for OAuth2 refresh tokens with environment detection.
 */
class OAuth2_Cookie_Config {

	/**
	 * Option name for storing cookie configuration.
	 */
	private const OPTION_NAME = 'oauth2_auth_cookie_config';

	/**
	 * Filter prefix for WordPress hooks.
	 */
	private const FILTER_PREFIX = 'oauth2_auth_cookie';

	/**
	 * Constant prefix for wp-config.php constants.
	 */
	private const CONSTANT_PREFIX = 'OAUTH2_AUTH_COOKIE';

	/**
	 * Get cookie configuration for current environment.
	 *
	 * Priority order:
	 * 1. Constants (OAUTH2_AUTH_COOKIE_*)
	 * 2. Filters (oauth2_auth_cookie_config / oauth2_auth_cookie_{key})
	 * 3. Saved options (admin panel)
	 * 4. Environment-based defaults (if auto-detection enabled)
	 * 5. Hard-coded defaults
	 *
	 * @return array{
	 *     enabled: bool,
	 *     name: string,
	 *     samesite: string,
	 *     secure: bool,
	 *     path: string,
	 *     domain: string,
	 *     httponly: bool,
	 *     lifetime: int,
	 *     environment: string,
	 *     auto_detect: bool
	 * }
	 */
	public static function get_config(): array {
		return CookieConfig::getConfig(
			self::OPTION_NAME,
			self::FILTER_PREFIX,
			self::CONSTANT_PREFIX
		);
	}

	/**
	 * Update cookie configuration.
	 *
	 * @param array<string, mixed> $config New configuration.
	 * @return bool True on success, false on failure.
	 */
	public static function update_config( array $config ): bool {
		return CookieConfig::updateConfig( $config, self::OPTION_NAME );
	}

	/**
	 * Get default configuration values for admin panel.
	 *
	 * @return array{
	 *     enabled: bool,
	 *     name: string,
	 *     samesite: string,
	 *     secure: string,
	 *     path: string,
	 *     domain: string,
	 *     httponly: bool,
	 *     lifetime: int,
	 *     auto_detect: bool
	 * }
	 */
	public static function get_defaults(): array {
		$defaults         = CookieConfig::getDefaults();
		$defaults['name'] = 'oauth2auth_session'; // Override default name for OAuth2 Auth.
		return $defaults;
	}

	/**
	 * Get current environment type.
	 *
	 * @return string
	 */
	public static function get_environment(): string {
		return CookieConfig::getEnvironment();
	}

	/**
	 * Check if current environment is development.
	 *
	 * @return bool
	 */
	public static function is_development(): bool {
		return CookieConfig::isDevelopment();
	}

	/**
	 * Check if current environment is production.
	 *
	 * @return bool
	 */
	public static function is_production(): bool {
		return CookieConfig::isProduction();
	}

	/**
	 * Clear configuration cache.
	 */
	public static function clear_cache(): void {
		CookieConfig::clearCache();
	}
}
