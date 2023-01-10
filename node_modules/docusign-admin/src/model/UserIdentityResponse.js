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
    define(['ApiClient', 'model/ErrorDetails'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ErrorDetails'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UserIdentityResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.ErrorDetails);
  }
}(this, function(ApiClient, ErrorDetails) {
  'use strict';


  /**
   * The UserIdentityResponse model module.
   * @module model/UserIdentityResponse
   */

  /**
   * Constructs a new <code>UserIdentityResponse</code>.
   * @alias module:model/UserIdentityResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UserIdentityResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserIdentityResponse} obj Optional instance to populate.
   * @return {module:model/UserIdentityResponse} The populated <code>UserIdentityResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('provider_id')) {
        obj['provider_id'] = ApiClient.convertToType(data['provider_id'], 'String');
      }
      if (data.hasOwnProperty('user_id')) {
        obj['user_id'] = ApiClient.convertToType(data['user_id'], 'String');
      }
      if (data.hasOwnProperty('immutable_id')) {
        obj['immutable_id'] = ApiClient.convertToType(data['immutable_id'], 'String');
      }
      if (data.hasOwnProperty('error_details')) {
        obj['error_details'] = ErrorDetails.constructFromObject(data['error_details']);
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} provider_id
   */
  exports.prototype['provider_id'] = undefined;
  /**
   * @member {String} user_id
   */
  exports.prototype['user_id'] = undefined;
  /**
   * @member {String} immutable_id
   */
  exports.prototype['immutable_id'] = undefined;
  /**
   * @member {module:model/ErrorDetails} error_details
   */
  exports.prototype['error_details'] = undefined;



  return exports;
}));


