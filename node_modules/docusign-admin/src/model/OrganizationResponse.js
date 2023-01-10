/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/DomainResponse', 'model/IdentityProvidersResponse', 'model/LinkResponse', 'model/OrganizationAccountResponse', 'model/OrganizationSimpleIdObject'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DomainResponse'), require('./IdentityProvidersResponse'), require('./LinkResponse'), require('./OrganizationAccountResponse'), require('./OrganizationSimpleIdObject'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DomainResponse, root.DocusignAdmin.IdentityProvidersResponse, root.DocusignAdmin.LinkResponse, root.DocusignAdmin.OrganizationAccountResponse, root.DocusignAdmin.OrganizationSimpleIdObject);
  }
}(this, function(ApiClient, DomainResponse, IdentityProvidersResponse, LinkResponse, OrganizationAccountResponse, OrganizationSimpleIdObject) {
  'use strict';


  /**
   * The OrganizationResponse model module.
   * @module model/OrganizationResponse
   */

  /**
   * Constructs a new <code>OrganizationResponse</code>.
   * @alias module:model/OrganizationResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationResponse} The populated <code>OrganizationResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('description')) {
        obj['description'] = ApiClient.convertToType(data['description'], 'String');
      }
      if (data.hasOwnProperty('default_account_id')) {
        obj['default_account_id'] = ApiClient.convertToType(data['default_account_id'], 'String');
      }
      if (data.hasOwnProperty('default_permission_profile_id')) {
        obj['default_permission_profile_id'] = ApiClient.convertToType(data['default_permission_profile_id'], 'Number');
      }
      if (data.hasOwnProperty('created_on')) {
        obj['created_on'] = ApiClient.convertToType(data['created_on'], 'Date');
      }
      if (data.hasOwnProperty('created_by')) {
        obj['created_by'] = ApiClient.convertToType(data['created_by'], 'String');
      }
      if (data.hasOwnProperty('last_modified_on')) {
        obj['last_modified_on'] = ApiClient.convertToType(data['last_modified_on'], 'Date');
      }
      if (data.hasOwnProperty('last_modified_by')) {
        obj['last_modified_by'] = ApiClient.convertToType(data['last_modified_by'], 'String');
      }
      if (data.hasOwnProperty('accounts')) {
        obj['accounts'] = ApiClient.convertToType(data['accounts'], [OrganizationAccountResponse]);
      }
      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [OrganizationSimpleIdObject]);
      }
      if (data.hasOwnProperty('reserved_domains')) {
        obj['reserved_domains'] = ApiClient.convertToType(data['reserved_domains'], [DomainResponse]);
      }
      if (data.hasOwnProperty('identity_providers')) {
        obj['identity_providers'] = ApiClient.convertToType(data['identity_providers'], [IdentityProvidersResponse]);
      }
      if (data.hasOwnProperty('links')) {
        obj['links'] = ApiClient.convertToType(data['links'], [LinkResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {String} description
   */
  exports.prototype['description'] = undefined;
  /**
   * @member {String} default_account_id
   */
  exports.prototype['default_account_id'] = undefined;
  /**
   * @member {Number} default_permission_profile_id
   */
  exports.prototype['default_permission_profile_id'] = undefined;
  /**
   * @member {Date} created_on
   */
  exports.prototype['created_on'] = undefined;
  /**
   * @member {String} created_by
   */
  exports.prototype['created_by'] = undefined;
  /**
   * @member {Date} last_modified_on
   */
  exports.prototype['last_modified_on'] = undefined;
  /**
   * @member {String} last_modified_by
   */
  exports.prototype['last_modified_by'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationAccountResponse>} accounts
   */
  exports.prototype['accounts'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationSimpleIdObject>} users
   */
  exports.prototype['users'] = undefined;
  /**
   * @member {Array.<module:model/DomainResponse>} reserved_domains
   */
  exports.prototype['reserved_domains'] = undefined;
  /**
   * @member {Array.<module:model/IdentityProvidersResponse>} identity_providers
   */
  exports.prototype['identity_providers'] = undefined;
  /**
   * @member {Array.<module:model/LinkResponse>} links
   */
  exports.prototype['links'] = undefined;



  return exports;
}));


