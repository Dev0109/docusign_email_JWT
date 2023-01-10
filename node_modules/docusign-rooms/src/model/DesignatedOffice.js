/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
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
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.DesignatedOffice = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DesignatedOffice model module.
   * @module model/DesignatedOffice
   */

  /**
   * Constructs a new <code>DesignatedOffice</code>.
   * @alias module:model/DesignatedOffice
   * @class
   * @param officeId {Number} 
   */
  var exports = function(officeId) {
    var _this = this;

    _this['officeId'] = officeId;
  };

  /**
   * Constructs a <code>DesignatedOffice</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DesignatedOffice} obj Optional instance to populate.
   * @return {module:model/DesignatedOffice} The populated <code>DesignatedOffice</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('officeId')) {
        obj['officeId'] = ApiClient.convertToType(data['officeId'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {Number} officeId
   */
  exports.prototype['officeId'] = undefined;



  return exports;
}));


