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
    define(['ApiClient', 'model/LinkResponse', 'model/SettingResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./LinkResponse'), require('./SettingResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DomainResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.LinkResponse, root.DocusignAdmin.SettingResponse);
  }
}(this, function(ApiClient, LinkResponse, SettingResponse) {
  'use strict';


  /**
   * The DomainResponse model module.
   * @module model/DomainResponse
   */

  /**
   * Constructs a new <code>DomainResponse</code>.
   * @alias module:model/DomainResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DomainResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DomainResponse} obj Optional instance to populate.
   * @return {module:model/DomainResponse} The populated <code>DomainResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('host_name')) {
        obj['host_name'] = ApiClient.convertToType(data['host_name'], 'String');
      }
      if (data.hasOwnProperty('txt_token')) {
        obj['txt_token'] = ApiClient.convertToType(data['txt_token'], 'String');
      }
      if (data.hasOwnProperty('identity_provider_id')) {
        obj['identity_provider_id'] = ApiClient.convertToType(data['identity_provider_id'], 'String');
      }
      if (data.hasOwnProperty('settings')) {
        obj['settings'] = ApiClient.convertToType(data['settings'], [SettingResponse]);
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
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {String} host_name
   */
  exports.prototype['host_name'] = undefined;
  /**
   * @member {String} txt_token
   */
  exports.prototype['txt_token'] = undefined;
  /**
   * @member {String} identity_provider_id
   */
  exports.prototype['identity_provider_id'] = undefined;
  /**
   * @member {Array.<module:model/SettingResponse>} settings
   */
  exports.prototype['settings'] = undefined;
  /**
   * @member {Array.<module:model/LinkResponse>} links
   */
  exports.prototype['links'] = undefined;



  return exports;
}));


