/**
 * WordPress REST Auth OAuth2 - Admin JavaScript
 * Enterprise OAuth2 client management and configuration
 */

jQuery(document).ready(function($) {
    'use strict';

    const wpRestAuthOAuth2 = window.wpRestAuthOAuth2 || {};

    /**
     * Initialize admin functionality
     */
    function init() {
        bindEvents();
        initTooltips();
        initClientManagement();
        initProxySettings();
        validateSettings();
    }

    /**
     * Bind event handlers
     */
    function bindEvents() {
        // Client management
        $('#add-oauth2-client').on('click', showAddClientModal);
        $('#save-oauth2-client').on('click', saveClient);
        $('#cancel-oauth2-client').on('click', hideClientModal);
        $(document).on('click', '.edit-client', editClient);
        $(document).on('click', '.delete-client', deleteClient);
        $(document).on('click', '.regenerate-secret', regenerateClientSecret);

        // Redirect URI management
        $('#add-redirect-uri').on('click', addRedirectUri);
        $(document).on('click', '.remove-redirect-uri', removeRedirectUri);

        // Proxy settings
        $('input[name="wp_rest_auth_oauth2_settings[proxy_enabled]"]').on('change', toggleProxySettings);
        $('select[name="wp_rest_auth_oauth2_settings[proxy_mode]"]').on('change', handleProxyModeChange);

        // Testing
        $('#test-oauth2-flow').on('click', testOAuth2Flow);

        // Copy to clipboard
        $('.copy-to-clipboard').on('click', copyToClipboard);

        // Form validation
        $('.wp-rest-auth-oauth2-form').on('submit', validateForm);

        // Real-time validation
        $('#client-id').on('blur', validateClientId);
        $('.redirect-uri-input').on('blur', validateRedirectUri);
    }

    /**
     * Initialize tooltips
     */
    function initTooltips() {
        $('.wp-rest-auth-oauth2-tooltip').tooltip({
            position: { my: 'left+10 center', at: 'right center' },
            tooltipClass: 'wp-rest-auth-oauth2-tooltip-content'
        });
    }

    /**
     * Initialize client management
     */
    function initClientManagement() {
        loadClients();
    }

    /**
     * Initialize proxy settings
     */
    function initProxySettings() {
        toggleProxySettings();
        handleProxyModeChange();
    }

    /**
     * Load OAuth2 clients
     */
    function loadClients() {
        $.ajax({
            url: wpRestAuthOAuth2.ajaxUrl,
            method: 'POST',
            data: {
                action: 'wp_rest_auth_oauth2_get_clients',
                nonce: wpRestAuthOAuth2.nonce
            }
        }).done(function(response) {
            if (response.success) {
                renderClientsTable(response.data);
            } else {
                showNotice('Failed to load OAuth2 clients: ' + response.data, 'error');
            }
        }).fail(function(xhr) {
            showNotice('Failed to load OAuth2 clients: ' + xhr.responseText, 'error');
        });
    }

    /**
     * Render clients table
     */
    function renderClientsTable(clients) {
        const $tbody = $('#oauth2-clients-table tbody');
        $tbody.empty();

        if (Object.keys(clients).length === 0) {
            $tbody.append(`
                <tr>
                    <td colspan="5" class="no-clients">No OAuth2 clients found. <a href="#" id="add-first-client">Add your first client</a></td>
                </tr>
            `);
            $('#add-first-client').on('click', showAddClientModal);
            return;
        }

        Object.entries(clients).forEach(([clientId, client]) => {
            const createdAt = new Date(client.created_at).toLocaleDateString();
            const redirectUris = client.redirect_uris.join('<br>');

            $tbody.append(`
                <tr data-client-id="${clientId}">
                    <td><code>${clientId}</code></td>
                    <td>${client.name}</td>
                    <td><small>${redirectUris}</small></td>
                    <td>${createdAt}</td>
                    <td class="actions">
                        <button type="button" class="button edit-client" data-client-id="${clientId}">Edit</button>
                        <button type="button" class="button regenerate-secret" data-client-id="${clientId}">Regenerate Secret</button>
                        <button type="button" class="button button-link-delete delete-client" data-client-id="${clientId}">Delete</button>
                    </td>
                </tr>
            `);
        });
    }

    /**
     * Show add client modal
     */
    function showAddClientModal(e) {
        e.preventDefault();
        resetClientForm();
        $('#client-modal-title').text('Add OAuth2 Client');
        $('#oauth2-client-modal').show();
        $('#client-id').focus();
    }

    /**
     * Edit client
     */
    function editClient(e) {
        e.preventDefault();

        const clientId = $(this).data('client-id');

        $.ajax({
            url: wpRestAuthOAuth2.ajaxUrl,
            method: 'POST',
            data: {
                action: 'wp_rest_auth_oauth2_get_client',
                client_id: clientId,
                nonce: wpRestAuthOAuth2.nonce
            }
        }).done(function(response) {
            if (response.success) {
                populateClientForm(response.data);
                $('#client-modal-title').text('Edit OAuth2 Client');
                $('#oauth2-client-modal').show();
            } else {
                showNotice('Failed to load client: ' + response.data, 'error');
            }
        });
    }

    /**
     * Save client
     */
    function saveClient(e) {
        e.preventDefault();

        const clientData = {
            client_id: $('#client-id').val(),
            client_name: $('#client-name').val(),
            redirect_uris: []
        };

        $('.redirect-uri-input').each(function() {
            const uri = $(this).val().trim();
            if (uri) {
                clientData.redirect_uris.push(uri);
            }
        });

        if (!validateClientData(clientData)) {
            return;
        }

        const $button = $(this);
        const originalText = $button.text();

        $button.prop('disabled', true).text('Saving...');

        $.ajax({
            url: wpRestAuthOAuth2.ajaxUrl,
            method: 'POST',
            data: {
                action: 'wp_rest_auth_oauth2_save_client',
                client_data: clientData,
                nonce: wpRestAuthOAuth2.nonce
            }
        }).done(function(response) {
            if (response.success) {
                showNotice('OAuth2 client saved successfully!', 'success');
                hideClientModal();
                loadClients();
            } else {
                showNotice('Failed to save client: ' + response.data, 'error');
            }
        }).fail(function(xhr) {
            showNotice('Failed to save client: ' + xhr.responseText, 'error');
        }).always(function() {
            $button.prop('disabled', false).text(originalText);
        });
    }

    /**
     * Delete client
     */
    function deleteClient(e) {
        e.preventDefault();

        const clientId = $(this).data('client-id');

        if (!confirm(`Are you sure you want to delete the client "${clientId}"? This action cannot be undone.`)) {
            return;
        }

        $.ajax({
            url: wpRestAuthOAuth2.ajaxUrl,
            method: 'POST',
            data: {
                action: 'wp_rest_auth_oauth2_delete_client',
                client_id: clientId,
                nonce: wpRestAuthOAuth2.nonce
            }
        }).done(function(response) {
            if (response.success) {
                showNotice('OAuth2 client deleted successfully!', 'success');
                loadClients();
            } else {
                showNotice('Failed to delete client: ' + response.data, 'error');
            }
        });
    }

    /**
     * Regenerate client secret
     */
    function regenerateClientSecret(e) {
        e.preventDefault();

        const clientId = $(this).data('client-id');

        if (!confirm(`Regenerate secret for client "${clientId}"? This will invalidate all existing tokens.`)) {
            return;
        }

        $.ajax({
            url: wpRestAuthOAuth2.ajaxUrl,
            method: 'POST',
            data: {
                action: 'wp_rest_auth_oauth2_regenerate_secret',
                client_id: clientId,
                nonce: wpRestAuthOAuth2.nonce
            }
        }).done(function(response) {
            if (response.success) {
                showNotice('Client secret regenerated successfully!', 'success');
                alert('New client secret: ' + response.data.client_secret + '\n\nPlease save this secret as it will not be shown again.');
            } else {
                showNotice('Failed to regenerate secret: ' + response.data, 'error');
            }
        });
    }

    /**
     * Add redirect URI input
     */
    function addRedirectUri(e) {
        e.preventDefault();

        const $container = $('#redirect-uris-container');
        const index = $container.children().length;

        $container.append(`
            <div class="redirect-uri-row">
                <input type="url" class="regular-text redirect-uri-input" name="redirect_uris[]" placeholder="https://example.com/callback" />
                <button type="button" class="button remove-redirect-uri">Remove</button>
            </div>
        `);
    }

    /**
     * Remove redirect URI input
     */
    function removeRedirectUri(e) {
        e.preventDefault();
        $(this).closest('.redirect-uri-row').remove();
    }

    /**
     * Toggle proxy settings
     */
    function toggleProxySettings() {
        const isEnabled = $('input[name="wp_rest_auth_oauth2_settings[proxy_enabled]"]:checked').val() === '1';
        $('.proxy-settings-group').toggle(isEnabled);
    }

    /**
     * Handle proxy mode change
     */
    function handleProxyModeChange() {
        const mode = $('select[name="wp_rest_auth_oauth2_settings[proxy_mode]"]').val();

        $('.proxy-mode-description').hide();
        $(`.proxy-mode-description[data-mode="${mode}"]`).show();
    }

    /**
     * Test OAuth2 flow
     */
    function testOAuth2Flow(e) {
        e.preventDefault();

        const $button = $(this);
        const originalText = $button.text();

        $button.prop('disabled', true).text('Testing...');

        // This would typically open a popup or redirect for OAuth2 testing
        showNotice('OAuth2 flow testing is available through the demo client endpoints.', 'info');

        setTimeout(() => {
            $button.prop('disabled', false).text(originalText);
        }, 2000);
    }

    /**
     * Utility functions
     */
    function hideClientModal() {
        $('#oauth2-client-modal').hide();
    }

    function resetClientForm() {
        $('#client-id').val('').prop('readonly', false);
        $('#client-name').val('');
        $('#redirect-uris-container').empty().append(`
            <div class="redirect-uri-row">
                <input type="url" class="regular-text redirect-uri-input" name="redirect_uris[]" placeholder="https://example.com/callback" />
                <button type="button" class="button remove-redirect-uri">Remove</button>
            </div>
        `);
    }

    function populateClientForm(client) {
        $('#client-id').val(client.client_id).prop('readonly', true);
        $('#client-name').val(client.name);

        const $container = $('#redirect-uris-container');
        $container.empty();

        client.redirect_uris.forEach(uri => {
            $container.append(`
                <div class="redirect-uri-row">
                    <input type="url" class="regular-text redirect-uri-input" name="redirect_uris[]" value="${uri}" />
                    <button type="button" class="button remove-redirect-uri">Remove</button>
                </div>
            `);
        });
    }

    function validateClientData(data) {
        if (!data.client_id.trim()) {
            showNotice('Client ID is required', 'error');
            return false;
        }

        if (!data.client_name.trim()) {
            showNotice('Client name is required', 'error');
            return false;
        }

        if (data.redirect_uris.length === 0) {
            showNotice('At least one redirect URI is required', 'error');
            return false;
        }

        return true;
    }

    function validateClientId() {
        const $input = $('#client-id');
        const value = $input.val().trim();

        if (!value) {
            showFieldError($input, 'Client ID is required');
            return false;
        }

        if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
            showFieldError($input, 'Client ID can only contain letters, numbers, underscores, and dashes');
            return false;
        }

        clearFieldError($input);
        return true;
    }

    function validateRedirectUri() {
        const $input = $(this);
        const value = $input.val().trim();

        if (!value) {
            return true; // Empty is okay, will be filtered out
        }

        try {
            const url = new URL(value);
            if (!['http:', 'https:'].includes(url.protocol)) {
                showFieldError($input, 'Only HTTP and HTTPS URLs are allowed');
                return false;
            }
        } catch (e) {
            showFieldError($input, 'Invalid URL format');
            return false;
        }

        clearFieldError($input);
        return true;
    }

    function copyToClipboard(e) {
        e.preventDefault();

        const $button = $(this);
        const targetSelector = $button.data('target');
        const $target = $(targetSelector);

        if ($target.length) {
            $target.select();
            document.execCommand('copy');

            const originalText = $button.text();
            $button.text('Copied!').addClass('copied');

            setTimeout(() => {
                $button.text(originalText).removeClass('copied');
            }, 2000);
        }
    }

    function showFieldError($field, message) {
        clearFieldError($field);
        $field.addClass('error').after(`<div class="field-error">${message}</div>`);
    }

    function clearFieldError($field) {
        $field.removeClass('error').next('.field-error').remove();
    }

    function showNotice(message, type = 'info') {
        const $notice = $(`
            <div class="notice notice-${type} is-dismissible">
                <p>${message}</p>
                <button type="button" class="notice-dismiss">
                    <span class="screen-reader-text">Dismiss this notice.</span>
                </button>
            </div>
        `);

        $('.wp-header-end').after($notice);

        setTimeout(() => {
            $notice.fadeOut(() => $notice.remove());
        }, 5000);
    }

    function validateForm(e) {
        // Form validation will be handled by specific form handlers
    }

    function validateSettings() {
        setTimeout(() => {
            validateClientId();
        }, 100);
    }

    // Initialize when document is ready
    init();
});