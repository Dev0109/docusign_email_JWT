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
    define(['ApiClient', 'model/ClosingStatus'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ClosingStatus'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalClosingStatuses = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.ClosingStatus);
  }
}(this, function(ApiClient, ClosingStatus) {
  'use strict';


  /**
   * The GlobalClosingStatuses model module.
   * @module model/GlobalClosingStatuses
   */

  /**
   * Constructs a new <code>GlobalClosingStatuses</code>.
   * @alias module:model/GlobalClosingStatuses
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalClosingStatuses</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalClosingStatuses} obj Optional instance to populate.
   * @return {module:model/GlobalClosingStatuses} The populated <code>GlobalClosingStatuses</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('closingStatuses')) {
        obj['closingStatuses'] = ApiClient.convertToType(data['closingStatuses'], [ClosingStatus]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/ClosingStatus>} closingStatuses
   */
  exports.prototype['closingStatuses'] = undefined;



  return exports;
}));


