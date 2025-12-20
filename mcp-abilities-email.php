<?php
/**
 * Plugin Name: MCP Abilities - Email
 * Plugin URI: https://github.com/bjornfix/mcp-abilities-email
 * Description: Email abilities for MCP. Gmail API integration with service account, inbox management, send/receive emails.
 * Version: 2.0.0
 * Author: Devenia
 * Author URI: https://devenia.com
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Requires at least: 6.9
 * Requires PHP: 8.0
 * Requires Plugins: abilities-api
 *
 * @package MCP_Abilities_Email
 */

declare( strict_types=1 );

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// =============================================================================
// GMAIL API HELPER CLASS
// =============================================================================

/**
 * Gmail API client using Google Service Account with domain-wide delegation.
 */
class MCP_Gmail_Client {

	/**
	 * Option name for storing Gmail configuration.
	 */
	const OPTION_NAME = 'mcp_gmail_config';

	/**
	 * Gmail API base URL.
	 */
	const API_BASE = 'https://gmail.googleapis.com/gmail/v1';

	/**
	 * Google OAuth2 token endpoint.
	 */
	const TOKEN_URL = 'https://oauth2.googleapis.com/token';

	/**
	 * Required Gmail API scopes.
	 */
	const SCOPES = array(
		'https://www.googleapis.com/auth/gmail.readonly',
		'https://www.googleapis.com/auth/gmail.send',
		'https://www.googleapis.com/auth/gmail.modify',
	);

	/**
	 * Cached access token.
	 *
	 * @var string|null
	 */
	private static ?string $access_token = null;

	/**
	 * Token expiration timestamp.
	 *
	 * @var int
	 */
	private static int $token_expires = 0;

	/**
	 * Get Gmail configuration.
	 *
	 * @return array|null Configuration array or null if not configured.
	 */
	public static function get_config(): ?array {
		$config = get_option( self::OPTION_NAME, null );
		if ( empty( $config ) || empty( $config['service_account'] ) || empty( $config['impersonate_email'] ) ) {
			return null;
		}
		return $config;
	}

	/**
	 * Save Gmail configuration.
	 *
	 * @param array $config Configuration array.
	 * @return bool Success.
	 */
	public static function save_config( array $config ): bool {
		// Clear cached token when config changes.
		self::$access_token = null;
		self::$token_expires = 0;
		delete_transient( 'mcp_gmail_access_token' );

		return update_option( self::OPTION_NAME, $config, false );
	}

	/**
	 * Base64 URL encode (JWT-safe).
	 *
	 * @param string $data Data to encode.
	 * @return string Encoded string.
	 */
	private static function base64url_encode( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Create a signed JWT for service account authentication.
	 *
	 * @param array  $service_account Service account JSON data.
	 * @param string $impersonate_email Email to impersonate.
	 * @return string|WP_Error JWT string or error.
	 */
	private static function create_jwt( array $service_account, string $impersonate_email ) {
		$now = time();

		$header = array(
			'alg' => 'RS256',
			'typ' => 'JWT',
		);

		$claims = array(
			'iss'   => $service_account['client_email'],
			'sub'   => $impersonate_email,
			'scope' => implode( ' ', self::SCOPES ),
			'aud'   => self::TOKEN_URL,
			'iat'   => $now,
			'exp'   => $now + 3600,
		);

		$header_encoded = self::base64url_encode( wp_json_encode( $header ) );
		$claims_encoded = self::base64url_encode( wp_json_encode( $claims ) );

		$signing_input = $header_encoded . '.' . $claims_encoded;

		// Sign with private key.
		$private_key = openssl_pkey_get_private( $service_account['private_key'] );
		if ( ! $private_key ) {
			return new WP_Error( 'invalid_key', 'Invalid private key in service account.' );
		}

		$signature = '';
		if ( ! openssl_sign( $signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256 ) ) {
			return new WP_Error( 'sign_failed', 'Failed to sign JWT.' );
		}

		return $signing_input . '.' . self::base64url_encode( $signature );
	}

	/**
	 * Get access token (cached).
	 *
	 * @return string|WP_Error Access token or error.
	 */
	public static function get_access_token() {
		// Check memory cache.
		if ( self::$access_token && self::$token_expires > time() + 60 ) {
			return self::$access_token;
		}

		// Check transient cache.
		$cached = get_transient( 'mcp_gmail_access_token' );
		if ( $cached && isset( $cached['token'], $cached['expires'] ) && $cached['expires'] > time() + 60 ) {
			self::$access_token = $cached['token'];
			self::$token_expires = $cached['expires'];
			return self::$access_token;
		}

		// Get fresh token.
		$config = self::get_config();
		if ( ! $config ) {
			return new WP_Error( 'not_configured', 'Gmail API not configured. Use gmail/configure first.' );
		}

		$jwt = self::create_jwt( $config['service_account'], $config['impersonate_email'] );
		if ( is_wp_error( $jwt ) ) {
			return $jwt;
		}

		$response = wp_remote_post(
			self::TOKEN_URL,
			array(
				'body'    => array(
					'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
					'assertion'  => $jwt,
				),
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'token_request_failed', 'Token request failed: ' . $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['access_token'] ) ) {
			$error = $body['error_description'] ?? $body['error'] ?? 'Unknown error';
			return new WP_Error( 'token_error', 'Failed to get access token: ' . $error );
		}

		self::$access_token = $body['access_token'];
		self::$token_expires = time() + ( (int) ( $body['expires_in'] ?? 3600 ) );

		// Cache in transient.
		set_transient(
			'mcp_gmail_access_token',
			array(
				'token'   => self::$access_token,
				'expires' => self::$token_expires,
			),
			self::$token_expires - time() - 60
		);

		return self::$access_token;
	}

	/**
	 * Make Gmail API request.
	 *
	 * @param string $endpoint API endpoint (after /users/me/).
	 * @param string $method   HTTP method.
	 * @param array  $body     Request body for POST/PUT.
	 * @param array  $query    Query parameters.
	 * @return array|WP_Error Response data or error.
	 */
	public static function api_request( string $endpoint, string $method = 'GET', array $body = array(), array $query = array() ) {
		$token = self::get_access_token();
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$url = self::API_BASE . '/users/me/' . $endpoint;
		if ( ! empty( $query ) ) {
			$url .= '?' . http_build_query( $query );
		}

		$args = array(
			'method'  => $method,
			'headers' => array(
				'Authorization' => 'Bearer ' . $token,
				'Content-Type'  => 'application/json',
			),
			'timeout' => 30,
		);

		if ( ! empty( $body ) && in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			$args['body'] = wp_json_encode( $body );
		}

		$response = wp_remote_request( $url, $args );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code >= 400 ) {
			$error = $data['error']['message'] ?? 'API error';
			return new WP_Error( 'api_error', "Gmail API error ($code): $error" );
		}

		return $data ?? array();
	}

	/**
	 * Parse email message parts to extract body.
	 *
	 * @param array $payload Message payload.
	 * @return array Array with 'text' and 'html' keys.
	 */
	public static function parse_message_body( array $payload ): array {
		$result = array(
			'text' => '',
			'html' => '',
		);

		if ( isset( $payload['body']['data'] ) && ! empty( $payload['body']['data'] ) ) {
			$mime_type = $payload['mimeType'] ?? 'text/plain';
			$decoded = base64_decode( strtr( $payload['body']['data'], '-_', '+/' ) );
			if ( str_contains( $mime_type, 'html' ) ) {
				$result['html'] = $decoded;
			} else {
				$result['text'] = $decoded;
			}
		}

		if ( isset( $payload['parts'] ) && is_array( $payload['parts'] ) ) {
			foreach ( $payload['parts'] as $part ) {
				$part_result = self::parse_message_body( $part );
				if ( ! empty( $part_result['text'] ) && empty( $result['text'] ) ) {
					$result['text'] = $part_result['text'];
				}
				if ( ! empty( $part_result['html'] ) && empty( $result['html'] ) ) {
					$result['html'] = $part_result['html'];
				}
			}
		}

		return $result;
	}

	/**
	 * Extract header value from message headers.
	 *
	 * @param array  $headers Headers array.
	 * @param string $name    Header name.
	 * @return string Header value or empty string.
	 */
	public static function get_header( array $headers, string $name ): string {
		foreach ( $headers as $header ) {
			if ( strcasecmp( $header['name'], $name ) === 0 ) {
				return $header['value'];
			}
		}
		return '';
	}

	/**
	 * Create RFC 2822 formatted email for sending.
	 *
	 * @param string $to      Recipient.
	 * @param string $subject Subject.
	 * @param string $body    Body (HTML).
	 * @param string $from    From address.
	 * @param array  $headers Additional headers.
	 * @return string Base64url encoded message.
	 */
	public static function create_message( string $to, string $subject, string $body, string $from, array $headers = array() ): string {
		$boundary = 'boundary_' . wp_generate_password( 16, false );

		$message = "From: $from\r\n";
		$message .= "To: $to\r\n";
		$message .= "Subject: $subject\r\n";
		$message .= "MIME-Version: 1.0\r\n";
		$message .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";

		foreach ( $headers as $key => $value ) {
			$message .= "$key: $value\r\n";
		}

		$message .= "\r\n";
		$message .= "--$boundary\r\n";
		$message .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
		$message .= wp_strip_all_tags( $body ) . "\r\n";
		$message .= "--$boundary\r\n";
		$message .= "Content-Type: text/html; charset=UTF-8\r\n\r\n";
		$message .= $body . "\r\n";
		$message .= "--$boundary--";

		return self::base64url_encode( $message );
	}
}

// =============================================================================
// PLUGIN INITIALIZATION
// =============================================================================

/**
 * Check if Abilities API is available.
 */
function mcp_email_check_dependencies(): bool {
	if ( ! function_exists( 'wp_register_ability' ) ) {
		add_action( 'admin_notices', function () {
			echo '<div class="notice notice-error"><p><strong>MCP Abilities - Email</strong> requires the <a href="https://github.com/WordPress/abilities-api">Abilities API</a> plugin to be installed and activated.</p></div>';
		} );
		return false;
	}
	return true;
}

/**
 * Register Email abilities.
 */
function mcp_register_email_abilities(): void {
	if ( ! mcp_email_check_dependencies() ) {
		return;
	}

	// =========================================================================
	// GMAIL - Configure
	// =========================================================================
	wp_register_ability(
		'gmail/configure',
		array(
			'label'               => 'Configure Gmail API',
			'description'         => 'Configures Gmail API with Google service account credentials for domain-wide delegation.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'service_account_json', 'impersonate_email' ),
				'properties'           => array(
					'service_account_json' => array(
						'type'        => 'string',
						'description' => 'Google service account JSON (as string) or path to JSON file.',
					),
					'impersonate_email'    => array(
						'type'        => 'string',
						'description' => 'Email address to impersonate (must be in the Workspace domain).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();

				$json_input = $input['service_account_json'] ?? '';
				$impersonate = sanitize_email( $input['impersonate_email'] ?? '' );

				if ( empty( $json_input ) || empty( $impersonate ) ) {
					return array(
						'success' => false,
						'message' => 'Both service_account_json and impersonate_email are required.',
					);
				}

				// Try to parse JSON - could be raw JSON or file path.
				if ( str_starts_with( trim( $json_input ), '{' ) ) {
					$service_account = json_decode( $json_input, true );
				} elseif ( file_exists( $json_input ) && is_readable( $json_input ) ) {
					$service_account = json_decode( file_get_contents( $json_input ), true );
				} else {
					return array(
						'success' => false,
						'message' => 'Invalid service account JSON. Provide raw JSON or valid file path.',
					);
				}

				if ( ! $service_account || empty( $service_account['client_email'] ) || empty( $service_account['private_key'] ) ) {
					return array(
						'success' => false,
						'message' => 'Invalid service account JSON structure. Required: client_email, private_key.',
					);
				}

				// Validate private key.
				$key = openssl_pkey_get_private( $service_account['private_key'] );
				if ( ! $key ) {
					return array(
						'success' => false,
						'message' => 'Invalid private key in service account JSON.',
					);
				}

				// Save configuration.
				$config = array(
					'service_account'   => $service_account,
					'impersonate_email' => $impersonate,
					'configured_at'     => gmdate( 'Y-m-d H:i:s' ),
				);

				MCP_Gmail_Client::save_config( $config );

				// Test the connection.
				$token = MCP_Gmail_Client::get_access_token();
				if ( is_wp_error( $token ) ) {
					return array(
						'success' => false,
						'message' => 'Configuration saved but authentication failed: ' . $token->get_error_message(),
					);
				}

				return array(
					'success' => true,
					'message' => "Gmail API configured successfully. Impersonating: $impersonate",
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - Get Status
	// =========================================================================
	wp_register_ability(
		'gmail/status',
		array(
			'label'               => 'Gmail API Status',
			'description'         => 'Check Gmail API configuration and connection status.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => new stdClass(),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'    => array( 'type' => 'boolean' ),
					'configured' => array( 'type' => 'boolean' ),
					'connected'  => array( 'type' => 'boolean' ),
					'email'      => array( 'type' => 'string' ),
					'message'    => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$config = MCP_Gmail_Client::get_config();

				if ( ! $config ) {
					return array(
						'success'    => true,
						'configured' => false,
						'connected'  => false,
						'email'      => '',
						'message'    => 'Gmail API not configured. Use gmail/configure to set up.',
					);
				}

				$token = MCP_Gmail_Client::get_access_token();
				if ( is_wp_error( $token ) ) {
					return array(
						'success'    => true,
						'configured' => true,
						'connected'  => false,
						'email'      => $config['impersonate_email'],
						'message'    => 'Configured but connection failed: ' . $token->get_error_message(),
					);
				}

				// Test with profile request.
				$profile = MCP_Gmail_Client::api_request( 'profile' );
				if ( is_wp_error( $profile ) ) {
					return array(
						'success'    => true,
						'configured' => true,
						'connected'  => false,
						'email'      => $config['impersonate_email'],
						'message'    => 'Token valid but API test failed: ' . $profile->get_error_message(),
					);
				}

				return array(
					'success'       => true,
					'configured'    => true,
					'connected'     => true,
					'email'         => $profile['emailAddress'] ?? $config['impersonate_email'],
					'messages_total' => (int) ( $profile['messagesTotal'] ?? 0 ),
					'threads_total' => (int) ( $profile['threadsTotal'] ?? 0 ),
					'message'       => 'Gmail API connected and working.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - List Messages
	// =========================================================================
	wp_register_ability(
		'gmail/list',
		array(
			'label'               => 'List Gmail Messages',
			'description'         => 'Lists emails from Gmail inbox with optional filtering.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => array(
					'query'      => array(
						'type'        => 'string',
						'description' => 'Gmail search query (e.g., "is:unread", "from:example@gmail.com", "subject:invoice").',
					),
					'max_results' => array(
						'type'        => 'integer',
						'default'     => 20,
						'minimum'     => 1,
						'maximum'     => 100,
						'description' => 'Maximum number of messages to return.',
					),
					'label_ids'  => array(
						'type'        => 'array',
						'items'       => array( 'type' => 'string' ),
						'description' => 'Filter by label IDs (e.g., ["INBOX", "UNREAD"]).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'  => array( 'type' => 'boolean' ),
					'messages' => array( 'type' => 'array' ),
					'count'    => array( 'type' => 'integer' ),
					'message'  => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();

				$query = array(
					'maxResults' => min( 100, max( 1, (int) ( $input['max_results'] ?? 20 ) ) ),
				);

				if ( ! empty( $input['query'] ) ) {
					$query['q'] = sanitize_text_field( $input['query'] );
				}

				if ( ! empty( $input['label_ids'] ) && is_array( $input['label_ids'] ) ) {
					$query['labelIds'] = array_map( 'sanitize_text_field', $input['label_ids'] );
				}

				$response = MCP_Gmail_Client::api_request( 'messages', 'GET', array(), $query );

				if ( is_wp_error( $response ) ) {
					return array(
						'success' => false,
						'message' => $response->get_error_message(),
					);
				}

				$messages = array();
				if ( ! empty( $response['messages'] ) ) {
					foreach ( $response['messages'] as $msg ) {
						// Get message metadata.
						$detail = MCP_Gmail_Client::api_request(
							'messages/' . $msg['id'],
							'GET',
							array(),
							array( 'format' => 'metadata', 'metadataHeaders' => array( 'From', 'To', 'Subject', 'Date' ) )
						);

						if ( ! is_wp_error( $detail ) ) {
							$headers = $detail['payload']['headers'] ?? array();
							$messages[] = array(
								'id'      => $msg['id'],
								'thread_id' => $msg['threadId'] ?? '',
								'from'    => MCP_Gmail_Client::get_header( $headers, 'From' ),
								'to'      => MCP_Gmail_Client::get_header( $headers, 'To' ),
								'subject' => MCP_Gmail_Client::get_header( $headers, 'Subject' ),
								'date'    => MCP_Gmail_Client::get_header( $headers, 'Date' ),
								'snippet' => $detail['snippet'] ?? '',
								'labels'  => $detail['labelIds'] ?? array(),
								'unread'  => in_array( 'UNREAD', $detail['labelIds'] ?? array(), true ),
							);
						}
					}
				}

				return array(
					'success'  => true,
					'messages' => $messages,
					'count'    => count( $messages ),
					'message'  => 'Retrieved ' . count( $messages ) . ' message(s).',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - Get Message
	// =========================================================================
	wp_register_ability(
		'gmail/get',
		array(
			'label'               => 'Get Gmail Message',
			'description'         => 'Retrieves full content of a Gmail message by ID.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'message_id' ),
				'properties'           => array(
					'message_id' => array(
						'type'        => 'string',
						'description' => 'Gmail message ID.',
					),
					'mark_read'  => array(
						'type'        => 'boolean',
						'default'     => false,
						'description' => 'Mark message as read after fetching.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'email'   => array( 'type' => 'object' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();
				$message_id = sanitize_text_field( $input['message_id'] ?? '' );

				if ( empty( $message_id ) ) {
					return array(
						'success' => false,
						'message' => 'message_id is required.',
					);
				}

				$response = MCP_Gmail_Client::api_request( 'messages/' . $message_id, 'GET', array(), array( 'format' => 'full' ) );

				if ( is_wp_error( $response ) ) {
					return array(
						'success' => false,
						'message' => $response->get_error_message(),
					);
				}

				$headers = $response['payload']['headers'] ?? array();
				$body = MCP_Gmail_Client::parse_message_body( $response['payload'] ?? array() );

				$email = array(
					'id'        => $response['id'],
					'thread_id' => $response['threadId'] ?? '',
					'from'      => MCP_Gmail_Client::get_header( $headers, 'From' ),
					'to'        => MCP_Gmail_Client::get_header( $headers, 'To' ),
					'cc'        => MCP_Gmail_Client::get_header( $headers, 'Cc' ),
					'subject'   => MCP_Gmail_Client::get_header( $headers, 'Subject' ),
					'date'      => MCP_Gmail_Client::get_header( $headers, 'Date' ),
					'body_text' => $body['text'],
					'body_html' => $body['html'],
					'labels'    => $response['labelIds'] ?? array(),
					'snippet'   => $response['snippet'] ?? '',
				);

				// Mark as read if requested.
				if ( ! empty( $input['mark_read'] ) && in_array( 'UNREAD', $response['labelIds'] ?? array(), true ) ) {
					MCP_Gmail_Client::api_request(
						'messages/' . $message_id . '/modify',
						'POST',
						array( 'removeLabelIds' => array( 'UNREAD' ) )
					);
				}

				return array(
					'success' => true,
					'email'   => $email,
					'message' => 'Email retrieved successfully.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - Send
	// =========================================================================
	wp_register_ability(
		'gmail/send',
		array(
			'label'               => 'Send Gmail',
			'description'         => 'Sends an email via Gmail API.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'to', 'subject', 'body' ),
				'properties'           => array(
					'to'      => array(
						'type'        => 'string',
						'description' => 'Recipient email address.',
					),
					'subject' => array(
						'type'        => 'string',
						'description' => 'Email subject.',
					),
					'body'    => array(
						'type'        => 'string',
						'description' => 'Email body (HTML supported).',
					),
					'cc'      => array(
						'type'        => 'string',
						'description' => 'CC recipients (comma-separated).',
					),
					'bcc'     => array(
						'type'        => 'string',
						'description' => 'BCC recipients (comma-separated).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'    => array( 'type' => 'boolean' ),
					'message_id' => array( 'type' => 'string' ),
					'message'    => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();

				$config = MCP_Gmail_Client::get_config();
				if ( ! $config ) {
					return array(
						'success' => false,
						'message' => 'Gmail API not configured.',
					);
				}

				$to = sanitize_text_field( $input['to'] ?? '' );
				$subject = sanitize_text_field( $input['subject'] ?? '' );
				$body = wp_kses_post( $input['body'] ?? '' );

				if ( empty( $to ) || empty( $subject ) || empty( $body ) ) {
					return array(
						'success' => false,
						'message' => 'to, subject, and body are required.',
					);
				}

				$headers = array();
				if ( ! empty( $input['cc'] ) ) {
					$headers['Cc'] = sanitize_text_field( $input['cc'] );
				}
				if ( ! empty( $input['bcc'] ) ) {
					$headers['Bcc'] = sanitize_text_field( $input['bcc'] );
				}

				$raw = MCP_Gmail_Client::create_message(
					$to,
					$subject,
					$body,
					$config['impersonate_email'],
					$headers
				);

				$response = MCP_Gmail_Client::api_request(
					'messages/send',
					'POST',
					array( 'raw' => $raw )
				);

				if ( is_wp_error( $response ) ) {
					return array(
						'success' => false,
						'message' => 'Failed to send: ' . $response->get_error_message(),
					);
				}

				return array(
					'success'    => true,
					'message_id' => $response['id'] ?? '',
					'thread_id'  => $response['threadId'] ?? '',
					'message'    => "Email sent successfully to $to",
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => false,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - Modify Labels (mark read/unread, star, etc.)
	// =========================================================================
	wp_register_ability(
		'gmail/modify',
		array(
			'label'               => 'Modify Gmail Message',
			'description'         => 'Modifies Gmail message labels (mark read/unread, star, archive, trash).',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'message_id' ),
				'properties'           => array(
					'message_id'      => array(
						'type'        => 'string',
						'description' => 'Gmail message ID.',
					),
					'add_labels'      => array(
						'type'        => 'array',
						'items'       => array( 'type' => 'string' ),
						'description' => 'Labels to add (e.g., ["STARRED", "IMPORTANT"]).',
					),
					'remove_labels'   => array(
						'type'        => 'array',
						'items'       => array( 'type' => 'string' ),
						'description' => 'Labels to remove (e.g., ["UNREAD", "INBOX"]).',
					),
					'mark_read'       => array(
						'type'        => 'boolean',
						'description' => 'Shortcut: mark as read (removes UNREAD label).',
					),
					'mark_unread'     => array(
						'type'        => 'boolean',
						'description' => 'Shortcut: mark as unread (adds UNREAD label).',
					),
					'archive'         => array(
						'type'        => 'boolean',
						'description' => 'Shortcut: archive message (removes INBOX label).',
					),
					'trash'           => array(
						'type'        => 'boolean',
						'description' => 'Shortcut: move to trash.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'labels'  => array( 'type' => 'array' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();
				$message_id = sanitize_text_field( $input['message_id'] ?? '' );

				if ( empty( $message_id ) ) {
					return array(
						'success' => false,
						'message' => 'message_id is required.',
					);
				}

				// Handle trash separately (different endpoint).
				if ( ! empty( $input['trash'] ) ) {
					$response = MCP_Gmail_Client::api_request( 'messages/' . $message_id . '/trash', 'POST' );
					if ( is_wp_error( $response ) ) {
						return array(
							'success' => false,
							'message' => $response->get_error_message(),
						);
					}
					return array(
						'success' => true,
						'labels'  => $response['labelIds'] ?? array(),
						'message' => 'Message moved to trash.',
					);
				}

				$add_labels = array();
				$remove_labels = array();

				// Process shortcuts.
				if ( ! empty( $input['mark_read'] ) ) {
					$remove_labels[] = 'UNREAD';
				}
				if ( ! empty( $input['mark_unread'] ) ) {
					$add_labels[] = 'UNREAD';
				}
				if ( ! empty( $input['archive'] ) ) {
					$remove_labels[] = 'INBOX';
				}

				// Process explicit labels.
				if ( ! empty( $input['add_labels'] ) && is_array( $input['add_labels'] ) ) {
					$add_labels = array_merge( $add_labels, $input['add_labels'] );
				}
				if ( ! empty( $input['remove_labels'] ) && is_array( $input['remove_labels'] ) ) {
					$remove_labels = array_merge( $remove_labels, $input['remove_labels'] );
				}

				if ( empty( $add_labels ) && empty( $remove_labels ) ) {
					return array(
						'success' => false,
						'message' => 'No label modifications specified.',
					);
				}

				$body = array();
				if ( ! empty( $add_labels ) ) {
					$body['addLabelIds'] = array_unique( $add_labels );
				}
				if ( ! empty( $remove_labels ) ) {
					$body['removeLabelIds'] = array_unique( $remove_labels );
				}

				$response = MCP_Gmail_Client::api_request( 'messages/' . $message_id . '/modify', 'POST', $body );

				if ( is_wp_error( $response ) ) {
					return array(
						'success' => false,
						'message' => $response->get_error_message(),
					);
				}

				return array(
					'success' => true,
					'labels'  => $response['labelIds'] ?? array(),
					'message' => 'Message labels updated.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// GMAIL - Reply
	// =========================================================================
	wp_register_ability(
		'gmail/reply',
		array(
			'label'               => 'Reply to Gmail',
			'description'         => 'Sends a reply to an existing Gmail thread.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'message_id', 'body' ),
				'properties'           => array(
					'message_id' => array(
						'type'        => 'string',
						'description' => 'Original message ID to reply to.',
					),
					'body'       => array(
						'type'        => 'string',
						'description' => 'Reply body (HTML supported).',
					),
					'reply_all'  => array(
						'type'        => 'boolean',
						'default'     => false,
						'description' => 'Reply to all recipients.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'    => array( 'type' => 'boolean' ),
					'message_id' => array( 'type' => 'string' ),
					'message'    => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();

				$config = MCP_Gmail_Client::get_config();
				if ( ! $config ) {
					return array(
						'success' => false,
						'message' => 'Gmail API not configured.',
					);
				}

				$message_id = sanitize_text_field( $input['message_id'] ?? '' );
				$body = wp_kses_post( $input['body'] ?? '' );

				if ( empty( $message_id ) || empty( $body ) ) {
					return array(
						'success' => false,
						'message' => 'message_id and body are required.',
					);
				}

				// Get original message to extract reply info.
				$original = MCP_Gmail_Client::api_request(
					'messages/' . $message_id,
					'GET',
					array(),
					array( 'format' => 'metadata', 'metadataHeaders' => array( 'From', 'To', 'Cc', 'Subject', 'Message-ID' ) )
				);

				if ( is_wp_error( $original ) ) {
					return array(
						'success' => false,
						'message' => 'Failed to get original message: ' . $original->get_error_message(),
					);
				}

				$headers = $original['payload']['headers'] ?? array();
				$original_from = MCP_Gmail_Client::get_header( $headers, 'From' );
				$original_subject = MCP_Gmail_Client::get_header( $headers, 'Subject' );
				$original_message_id = MCP_Gmail_Client::get_header( $headers, 'Message-ID' );

				// Determine reply recipient.
				$to = $original_from;

				// Build subject with Re: prefix.
				$subject = $original_subject;
				if ( ! str_starts_with( strtolower( $subject ), 're:' ) ) {
					$subject = 'Re: ' . $subject;
				}

				// Build reply headers.
				$reply_headers = array();
				if ( ! empty( $original_message_id ) ) {
					$reply_headers['In-Reply-To'] = $original_message_id;
					$reply_headers['References'] = $original_message_id;
				}

				// Handle reply-all.
				if ( ! empty( $input['reply_all'] ) ) {
					$original_to = MCP_Gmail_Client::get_header( $headers, 'To' );
					$original_cc = MCP_Gmail_Client::get_header( $headers, 'Cc' );
					if ( ! empty( $original_cc ) ) {
						$reply_headers['Cc'] = $original_cc;
					}
				}

				$raw = MCP_Gmail_Client::create_message(
					$to,
					$subject,
					$body,
					$config['impersonate_email'],
					$reply_headers
				);

				$response = MCP_Gmail_Client::api_request(
					'messages/send',
					'POST',
					array(
						'raw'      => $raw,
						'threadId' => $original['threadId'] ?? '',
					)
				);

				if ( is_wp_error( $response ) ) {
					return array(
						'success' => false,
						'message' => 'Failed to send reply: ' . $response->get_error_message(),
					);
				}

				return array(
					'success'    => true,
					'message_id' => $response['id'] ?? '',
					'thread_id'  => $response['threadId'] ?? '',
					'message'    => "Reply sent successfully to $to",
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => false,
				),
			),
		)
	);

	// =========================================================================
	// Keep original WordPress email abilities for fallback
	// =========================================================================

	// EMAIL - Send (WordPress wp_mail)
	wp_register_ability(
		'email/send',
		array(
			'label'               => 'Send Email (WordPress)',
			'description'         => 'Sends an email using WordPress wp_mail(). Use gmail/send for Gmail API.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'to', 'subject', 'message' ),
				'properties'           => array(
					'to'          => array(
						'type'        => 'string',
						'description' => 'Recipient email address(es).',
					),
					'subject'     => array(
						'type'        => 'string',
						'description' => 'Email subject line.',
					),
					'message'     => array(
						'type'        => 'string',
						'description' => 'Email body content.',
					),
					'html'        => array(
						'type'        => 'boolean',
						'default'     => true,
						'description' => 'Send as HTML email.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = array() ): array {
				$input = is_array( $input ) ? $input : array();

				$to = sanitize_text_field( $input['to'] ?? '' );
				$subject = sanitize_text_field( $input['subject'] ?? '' );
				$message = wp_kses_post( $input['message'] ?? '' );

				if ( empty( $to ) || empty( $subject ) || empty( $message ) ) {
					return array(
						'success' => false,
						'message' => 'to, subject, and message are required.',
					);
				}

				$headers = array();
				if ( ! empty( $input['html'] ) || ! isset( $input['html'] ) ) {
					$headers[] = 'Content-Type: text/html; charset=UTF-8';
				}

				$sent = wp_mail( $to, $subject, $message, $headers );

				return array(
					'success' => $sent,
					'message' => $sent ? "Email sent to $to" : 'Failed to send email.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => false,
				),
			),
		)
	);
}
add_action( 'wp_abilities_api_init', 'mcp_register_email_abilities' );
