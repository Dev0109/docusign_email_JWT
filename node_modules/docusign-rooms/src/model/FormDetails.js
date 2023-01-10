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
    root.DocusignRooms.FormDetails = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The FormDetails model module.
   * @module model/FormDetails
   */

  /**
   * Constructs a new <code>FormDetails</code>.
   * @alias module:model/FormDetails
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>FormDetails</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/FormDetails} obj Optional instance to populate.
   * @return {module:model/FormDetails} The populated <code>FormDetails</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('formId')) {
        obj['formId'] = ApiClient.convertToType(data['formId'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('createdDate')) {
        obj['createdDate'] = ApiClient.convertToType(data['createdDate'], 'Date');
      }
      if (data.hasOwnProperty('lastUpdatedDate')) {
        obj['lastUpdatedDate'] = ApiClient.convertToType(data['lastUpdatedDate'], 'Date');
      }
      if (data.hasOwnProperty('availableOnDate')) {
        obj['availableOnDate'] = ApiClient.convertToType(data['availableOnDate'], 'Date');
      }
      if (data.hasOwnProperty('ownerName')) {
        obj['ownerName'] = ApiClient.convertToType(data['ownerName'], 'String');
      }
      if (data.hasOwnProperty('version')) {
        obj['version'] = ApiClient.convertToType(data['version'], 'String');
      }
      if (data.hasOwnProperty('numberOfPages')) {
        obj['numberOfPages'] = ApiClient.convertToType(data['numberOfPages'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} formId
   */
  exports.prototype['formId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Date} createdDate
   */
  exports.prototype['createdDate'] = undefined;
  /**
   * @member {Date} lastUpdatedDate
   */
  exports.prototype['lastUpdatedDate'] = undefined;
  /**
   * @member {Date} availableOnDate
   */
  exports.prototype['availableOnDate'] = undefined;
  /**
   * @member {String} ownerName
   */
  exports.prototype['ownerName'] = undefined;
  /**
   * @member {String} version
   */
  exports.prototype['version'] = undefined;
  /**
   * @member {Number} numberOfPages
   */
  exports.prototype['numberOfPages'] = undefined;



  return exports;
}));


