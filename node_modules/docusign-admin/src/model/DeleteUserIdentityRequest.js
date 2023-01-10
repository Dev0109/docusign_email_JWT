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
    define(['ApiClient', 'model/UserIdentityRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UserIdentityRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DeleteUserIdentityRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.UserIdentityRequest);
  }
}(this, function(ApiClient, UserIdentityRequest) {
  'use strict';


  /**
   * The DeleteUserIdentityRequest model module.
   * @module model/DeleteUserIdentityRequest
   */

  /**
   * Constructs a new <code>DeleteUserIdentityRequest</code>.
   * @alias module:model/DeleteUserIdentityRequest
   * @class
   * @param identities {Array.<module:model/UserIdentityRequest>} 
   */
  var exports = function(identities) {
    var _this = this;

    _this['identities'] = identities;
  };

  /**
   * Constructs a <code>DeleteUserIdentityRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DeleteUserIdentityRequest} obj Optional instance to populate.
   * @return {module:model/DeleteUserIdentityRequest} The populated <code>DeleteUserIdentityRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('identities')) {
        obj['identities'] = ApiClient.convertToType(data['identities'], [UserIdentityRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/UserIdentityRequest>} identities
   */
  exports.prototype['identities'] = undefined;



  return exports;
}));


