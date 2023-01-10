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
    define(['ApiClient', 'model/DeleteMembershipResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DeleteMembershipResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DeleteMembershipsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DeleteMembershipResponse);
  }
}(this, function(ApiClient, DeleteMembershipResponse) {
  'use strict';


  /**
   * The DeleteMembershipsResponse model module.
   * @module model/DeleteMembershipsResponse
   */

  /**
   * Constructs a new <code>DeleteMembershipsResponse</code>.
   * @alias module:model/DeleteMembershipsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DeleteMembershipsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DeleteMembershipsResponse} obj Optional instance to populate.
   * @return {module:model/DeleteMembershipsResponse} The populated <code>DeleteMembershipsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('success')) {
        obj['success'] = ApiClient.convertToType(data['success'], 'Boolean');
      }
      if (data.hasOwnProperty('accounts')) {
        obj['accounts'] = ApiClient.convertToType(data['accounts'], [DeleteMembershipResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} success
   */
  exports.prototype['success'] = undefined;
  /**
   * @member {Array.<module:model/DeleteMembershipResponse>} accounts
   */
  exports.prototype['accounts'] = undefined;



  return exports;
}));


