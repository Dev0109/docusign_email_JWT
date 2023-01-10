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
    define(['ApiClient', 'model/DeleteMembershipRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DeleteMembershipRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DeleteMembershipsRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DeleteMembershipRequest);
  }
}(this, function(ApiClient, DeleteMembershipRequest) {
  'use strict';


  /**
   * The DeleteMembershipsRequest model module.
   * @module model/DeleteMembershipsRequest
   */

  /**
   * Constructs a new <code>DeleteMembershipsRequest</code>.
   * @alias module:model/DeleteMembershipsRequest
   * @class
   * @param accounts {Array.<module:model/DeleteMembershipRequest>} 
   */
  var exports = function(accounts) {
    var _this = this;

    _this['accounts'] = accounts;
  };

  /**
   * Constructs a <code>DeleteMembershipsRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DeleteMembershipsRequest} obj Optional instance to populate.
   * @return {module:model/DeleteMembershipsRequest} The populated <code>DeleteMembershipsRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('accounts')) {
        obj['accounts'] = ApiClient.convertToType(data['accounts'], [DeleteMembershipRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/DeleteMembershipRequest>} accounts
   */
  exports.prototype['accounts'] = undefined;



  return exports;
}));


