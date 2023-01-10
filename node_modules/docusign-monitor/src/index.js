/**
 * Monitor API
 * An API for an integrator to access the features of DocuSign Monitor
 *
 * OpenAPI spec version: v2.0
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */
(function(factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['Configuration', 'ApiClient', 'model/AggregateResult', 'model/AggregateResultResult', 'model/CursoredResult', 'model/WebQuery', 'api/DataSetApi'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('./Configuration'), require('./ApiClient'), require('./model/AggregateResult'), require('./model/AggregateResultResult'), require('./model/CursoredResult'), require('./model/WebQuery'), require('./api/DataSetApi'));
  }
}(function(Configuration, ApiClient, AggregateResult, AggregateResultResult, CursoredResult, WebQuery, DataSetApi) {
  'use strict';

  /**
   * DocuSign Node.js API client..<br>
   * The <code>index</code> module provides access to constructors for all the classes which comprise the public API.
   * <p>
   * An AMD (recommended!) or CommonJS application will generally do something equivalent to the following:
   * <pre>
   * var DocusignMonitor = require('index'); // See note below*.
   * var xxxSvc = new DocusignMonitor.XxxApi(); // Allocate the API class we're going to use.
   * var yyyModel = new DocusignMonitor.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * <em>*NOTE: For a top-level AMD script, use require(['index'], function(){...})
   * and put the application logic within the callback function.</em>
   * </p>
   * <p>
   * A non-AMD browser application (discouraged) might do something like this:
   * <pre>
   * var xxxSvc = new DocusignMonitor.XxxApi(); // Allocate the API class we're going to use.
   * var yyy = new DocusignMonitor.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * </p>
   * @module index
   */
  var exports = {
	/**
	 * The configuration constructor.
	 * @property {module:Configuration}
	 */
	 Configuration: Configuration,
	/**
     * The ApiClient constructor.
     * @property {module:ApiClient}
     */
    ApiClient: ApiClient,
    /**
     * The AggregateResult model constructor.
     * @property {module:model/AggregateResult}
     */
    AggregateResult: AggregateResult,
    /**
     * The AggregateResultResult model constructor.
     * @property {module:model/AggregateResultResult}
     */
    AggregateResultResult: AggregateResultResult,
    /**
     * The CursoredResult model constructor.
     * @property {module:model/CursoredResult}
     */
    CursoredResult: CursoredResult,
    /**
     * The WebQuery model constructor.
     * @property {module:model/WebQuery}
     */
    WebQuery: WebQuery,
    /**
     * The DataSetApi service constructor.
     * @property {module:api/DataSetApi}
     */
    DataSetApi: DataSetApi
  };

  return exports;
}));