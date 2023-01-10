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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.ForceActivateMembershipRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ForceActivateMembershipRequest model module.
   * @module model/ForceActivateMembershipRequest
   */

  /**
   * Constructs a new <code>ForceActivateMembershipRequest</code>.
   * @alias module:model/ForceActivateMembershipRequest
   * @class
   * @param siteId {Number} 
   */
  var exports = function(siteId) {
    var _this = this;

    _this['site_id'] = siteId;
  };

  /**
   * Constructs a <code>ForceActivateMembershipRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ForceActivateMembershipRequest} obj Optional instance to populate.
   * @return {module:model/ForceActivateMembershipRequest} The populated <code>ForceActivateMembershipRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;



  return exports;
}));


