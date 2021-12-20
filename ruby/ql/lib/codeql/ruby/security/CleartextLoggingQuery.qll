/**
 * Provides a taint-tracking configuration for "Clear-text logging of sensitive information".
 *
 * Note, for performance reasons: only import this file if
 * `CleartextLogging::Configuration` is needed, otherwise
 * `CleartextLoggingCustomizations` should be imported instead.
 */

private import ruby
private import codeql.ruby.DataFlow
private import codeql.ruby.TaintTracking
import CleartextLoggingCustomizations::CleartextLogging

/**
 * Provides a taint-tracking configuration for detecting "Clear-text logging of sensitive information".
 */
module CleartextLogging {
  import CleartextLoggingCustomizations::CleartextLogging

  /**
   * A taint-tracking configuration for detecting "Clear-text logging of sensitive information".
   */
  class Configuration extends TaintTracking::Configuration {
    Configuration() { this = "CleartextLogging" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    override predicate isSanitizer(DataFlow::Node node) {
      super.isSanitizer(node)
      or
      node instanceof Sanitizer
    }
  }
}
