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
    define(['ApiClient', 'model/TaskResponsibilityType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TaskResponsibilityType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalTaskResponsibilityTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TaskResponsibilityType);
  }
}(this, function(ApiClient, TaskResponsibilityType) {
  'use strict';


  /**
   * The GlobalTaskResponsibilityTypes model module.
   * @module model/GlobalTaskResponsibilityTypes
   */

  /**
   * Constructs a new <code>GlobalTaskResponsibilityTypes</code>.
   * @alias module:model/GlobalTaskResponsibilityTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalTaskResponsibilityTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalTaskResponsibilityTypes} obj Optional instance to populate.
   * @return {module:model/GlobalTaskResponsibilityTypes} The populated <code>GlobalTaskResponsibilityTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskResponsibilityTypes')) {
        obj['taskResponsibilityTypes'] = ApiClient.convertToType(data['taskResponsibilityTypes'], [TaskResponsibilityType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TaskResponsibilityType>} taskResponsibilityTypes
   */
  exports.prototype['taskResponsibilityTypes'] = undefined;



  return exports;
}));


