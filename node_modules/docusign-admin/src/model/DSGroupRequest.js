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
    root.DocusignAdmin.DSGroupRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DSGroupRequest model module.
   * @module model/DSGroupRequest
   */

  /**
   * Constructs a new <code>DSGroupRequest</code>.
   * @alias module:model/DSGroupRequest
   * @class
   * @param dsGroupId {String} 
   */
  var exports = function(dsGroupId) {
    var _this = this;

    _this['ds_group_id'] = dsGroupId;
  };

  /**
   * Constructs a <code>DSGroupRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupRequest} obj Optional instance to populate.
   * @return {module:model/DSGroupRequest} The populated <code>DSGroupRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('ds_group_id')) {
        obj['ds_group_id'] = ApiClient.convertToType(data['ds_group_id'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} ds_group_id
   */
  exports.prototype['ds_group_id'] = undefined;



  return exports;
}));


