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
    define(['ApiClient', 'model/TaskListSummary'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TaskListSummary'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.TaskListSummaryList = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TaskListSummary);
  }
}(this, function(ApiClient, TaskListSummary) {
  'use strict';


  /**
   * The TaskListSummaryList model module.
   * @module model/TaskListSummaryList
   */

  /**
   * Constructs a new <code>TaskListSummaryList</code>.
   * @alias module:model/TaskListSummaryList
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>TaskListSummaryList</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/TaskListSummaryList} obj Optional instance to populate.
   * @return {module:model/TaskListSummaryList} The populated <code>TaskListSummaryList</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskListSummaries')) {
        obj['taskListSummaries'] = ApiClient.convertToType(data['taskListSummaries'], [TaskListSummary]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TaskListSummary>} taskListSummaries
   */
  exports.prototype['taskListSummaries'] = undefined;



  return exports;
}));


