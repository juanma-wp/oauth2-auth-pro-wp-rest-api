<?php
/**
 * OAuth2 Cookie Configuration Class
 *
 * Provides environment-aware cookie configuration for OAuth2 refresh tokens.
 * Automatically adjusts cookie security settings based on environment (development/production)
 * with optional manual overrides via WordPress admin settings.
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

/**
 * OAuth2 Cookie Configuration Class.
 *
 * Manages cookie security settings for OAuth2 refresh tokens with environment detection.
 */
class OAuth2_Cookie_Config {

	/**
	 * Option name for storing cookie configuration.
	 */
	private const OPTION_NAME = 'oauth2_auth_cookie_config';

	/**
	 * Environment types.
	 */
	private const ENV_DEVELOPMENT = 'development';
	private const ENV_STAGING     = 'staging';
	private const ENV_PRODUCTION  = 'production';

	/**
	 * Cookie configuration cache.
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $config_cache = null;

	/**
	 * Get cookie configuration for current environment.
	 *
	 * @return array{
	 *     samesite: string,
	 *     secure: bool,
	 *     path: string,
	 *     domain: string,
	 *     httponly: bool
	 * }
	 */
	public static function get_config(): array {
		if ( null !== self::$config_cache ) {
			return self::$config_cache;
		}

		$saved_config = get_option( self::OPTION_NAME, array() );
		$environment  = self::detect_environment();

		$config = array(
			'samesite' => self::resolve_samesite( $saved_config, $environment ),
			'secure'   => self::resolve_secure( $saved_config, $environment ),
			'path'     => self::resolve_path( $saved_config, $environment ),
			'domain'   => self::resolve_domain( $saved_config, $environment ),
			'httponly' => self::resolve_httponly( $saved_config ),
		);

		self::$config_cache = $config;
		return $config;
	}

	/**
	 * Detect current environment.
	 *
	 * @return string One of: 'development', 'staging', 'production'
	 */
	private static function detect_environment(): string {
		// Use WordPress environment type if available (WP 5.5+)
		if ( function_exists( 'wp_get_environment_type' ) ) {
			$wp_env = wp_get_environment_type();
			// Normalize 'local' to 'development' since they should behave the same
			if ( 'local' === $wp_env ) {
				return self::ENV_DEVELOPMENT;
			}
			// Only return if it matches one of our expected values
			if ( in_array( $wp_env, array( self::ENV_DEVELOPMENT, self::ENV_STAGING, self::ENV_PRODUCTION ), true ) ) {
				return $wp_env;
			}
			// Fall through to manual detection if unexpected value
		}

		// Fallback detection based on domain and WP_DEBUG
		$host = isset( $_SERVER['HTTP_HOST'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) ) : '';

		// Development indicators
		if (
			in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) ||
			str_ends_with( $host, '.local' ) ||
			str_ends_with( $host, '.test' ) ||
			str_ends_with( $host, '.localhost' ) ||
			( defined( 'WP_DEBUG' ) && WP_DEBUG )
		) {
			return self::ENV_DEVELOPMENT;
		}

		// Staging indicators
		if (
			str_contains( $host, 'staging' ) ||
			str_contains( $host, 'dev' ) ||
			str_contains( $host, 'test' )
		) {
			return self::ENV_STAGING;
		}

		return self::ENV_PRODUCTION;
	}

	/**
	 * Resolve SameSite attribute.
	 *
	 * @param array<string, mixed> $saved_config Saved configuration.
	 * @param string               $environment  Current environment.
	 * @return string 'None', 'Lax', or 'Strict'
	 */
	private static function resolve_samesite( array $saved_config, string $environment ): string {
		// Check for explicit override
		if ( isset( $saved_config['samesite'] ) && 'auto' !== $saved_config['samesite'] ) {
			return self::validate_samesite( $saved_config['samesite'] );
		}

		// Auto-detect based on environment
		switch ( $environment ) {
			case self::ENV_DEVELOPMENT:
				// Development: Allow cross-origin for SPAs on different ports
				return 'None';

			case self::ENV_STAGING:
				// Staging: Relaxed for testing
				return 'Lax';

			case self::ENV_PRODUCTION:
			default:
				// Production: Strict for maximum security
				return 'Strict';
		}
	}

	/**
	 * Resolve Secure attribute.
	 *
	 * @param array<string, mixed> $saved_config Saved configuration.
	 * @param string               $environment  Current environment.
	 * @return bool
	 */
	private static function resolve_secure( array $saved_config, string $environment ): bool {
		// Check for explicit override
		if ( isset( $saved_config['secure'] ) && 'auto' !== $saved_config['secure'] ) {
			// Handle string '1' and '0' from admin settings
			if ( '0' === $saved_config['secure'] || 0 === $saved_config['secure'] || false === $saved_config['secure'] ) {
				return false;
			}
			return (bool) $saved_config['secure'];
		}

		// Auto-detect based on environment and SSL
		if ( self::ENV_DEVELOPMENT === $environment ) {
			// Development: Only secure if actually using HTTPS
			return is_ssl();
		}

		// Staging/Production: Always require HTTPS
		return true;
	}

	/**
	 * Resolve cookie path.
	 *
	 * @param array<string, mixed> $saved_config Saved configuration.
	 * @param string               $environment  Current environment.
	 * @return string
	 */
	private static function resolve_path( array $saved_config, string $environment ): string {
		// Check for explicit override
		if ( isset( $saved_config['path'] ) && 'auto' !== $saved_config['path'] ) {
			return sanitize_text_field( $saved_config['path'] );
		}

		// Auto-detect based on environment
		if ( self::ENV_DEVELOPMENT === $environment ) {
			// Development: Broad path for easier cross-origin access
			return '/';
		}

		// Staging/Production: Restricted path for security
		return '/wp-json/oauth2/v1/';
	}

	/**
	 * Resolve cookie domain.
	 *
	 * @param array<string, mixed> $saved_config Saved configuration.
	 * @param string               $environment  Current environment.
	 * @return string
	 */
	private static function resolve_domain( array $saved_config, string $environment ): string {
		// Check for explicit override
		if ( isset( $saved_config['domain'] ) && 'auto' !== $saved_config['domain'] ) {
			return sanitize_text_field( $saved_config['domain'] );
		}

		// Auto-detect based on environment
		if ( self::ENV_DEVELOPMENT === $environment ) {
			// Development: Empty domain for localhost
			return '';
		}

		// Staging/Production: Empty (defaults to current domain)
		return '';
	}

	/**
	 * Resolve HttpOnly attribute.
	 *
	 * @param array<string, mixed> $saved_config Saved configuration.
	 * @return bool
	 */
	private static function resolve_httponly( array $saved_config ): bool {
		// HttpOnly should ALWAYS be true for security
		// Only allow override in very specific debugging scenarios
		if ( isset( $saved_config['httponly'] ) && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			return (bool) $saved_config['httponly'];
		}

		return true;
	}

	/**
	 * Validate SameSite value.
	 *
	 * @param string $value Value to validate.
	 * @return string Valid SameSite value
	 */
	private static function validate_samesite( string $value ): string {
		$valid = array( 'None', 'Lax', 'Strict' );
		return in_array( $value, $valid, true ) ? $value : 'Strict';
	}

	/**
	 * Update cookie configuration.
	 *
	 * @param array<string, mixed> $config New configuration.
	 * @return bool True on success, false on failure.
	 */
	public static function update_config( array $config ): bool {
		self::$config_cache = null; // Clear cache
		return update_option( self::OPTION_NAME, $config );
	}

	/**
	 * Get default configuration values.
	 *
	 * @return array{
	 *     samesite: string,
	 *     secure: string,
	 *     path: string,
	 *     domain: string,
	 *     httponly: bool
	 * }
	 */
	public static function get_defaults(): array {
		return array(
			'samesite' => 'auto',
			'secure'   => 'auto',
			'path'     => 'auto',
			'domain'   => 'auto',
			'httponly' => true,
		);
	}

	/**
	 * Get current environment type.
	 *
	 * @return string
	 */
	public static function get_environment(): string {
		return self::detect_environment();
	}

	/**
	 * Check if current environment is development.
	 *
	 * @return bool
	 */
	public static function is_development(): bool {
		return self::ENV_DEVELOPMENT === self::detect_environment();
	}

	/**
	 * Check if current environment is production.
	 *
	 * @return bool
	 */
	public static function is_production(): bool {
		return self::ENV_PRODUCTION === self::detect_environment();
	}

	/**
	 * Clear configuration cache.
	 */
	public static function clear_cache(): void {
		self::$config_cache = null;
	}
}
