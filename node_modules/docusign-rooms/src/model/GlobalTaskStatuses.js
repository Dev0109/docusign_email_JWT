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
    define(['ApiClient', 'model/TaskStatus'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TaskStatus'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalTaskStatuses = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TaskStatus);
  }
}(this, function(ApiClient, TaskStatus) {
  'use strict';


  /**
   * The GlobalTaskStatuses model module.
   * @module model/GlobalTaskStatuses
   */

  /**
   * Constructs a new <code>GlobalTaskStatuses</code>.
   * @alias module:model/GlobalTaskStatuses
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalTaskStatuses</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalTaskStatuses} obj Optional instance to populate.
   * @return {module:model/GlobalTaskStatuses} The populated <code>GlobalTaskStatuses</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskStatuses')) {
        obj['taskStatuses'] = ApiClient.convertToType(data['taskStatuses'], [TaskStatus]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TaskStatus>} taskStatuses
   */
  exports.prototype['taskStatuses'] = undefined;



  return exports;
}));


