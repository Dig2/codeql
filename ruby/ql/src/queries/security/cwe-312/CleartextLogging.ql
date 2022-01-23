/**
 * @name Clear-text logging of sensitive information
 * @description Logging sensitive information without encryption or hashing can
 *              expose it to an attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id rb/clear-text-logging-sensitive-data
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 *       external/cwe/cwe-532
 */

import ruby
import codeql.ruby.security.CleartextLoggingQuery
import codeql.ruby.DataFlow
import DataFlow::PathGraph

from CleartextLogging::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "$@ is logged here, src: " + source.getNode().getLocation() + " sink: " +
    sink.getNode().getLocation(), source.getNode(), "Sensitive data"
