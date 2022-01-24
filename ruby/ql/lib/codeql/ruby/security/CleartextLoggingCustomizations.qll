/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * cleartext logging of sensitive information, as well as extension points for
 * adding your own.
 */

private import ruby
private import codeql.ruby.DataFlow
private import codeql.ruby.TaintTracking::TaintTracking
private import codeql.ruby.Concepts
private import codeql.ruby.dataflow.RemoteFlowSources
private import internal.SensitiveDataHeuristics::HeuristicNames

module CleartextLogging {
  /**
   * A data flow source for cleartext logging of sensitive information.
   */
  abstract class Source extends DataFlow::Node {
    /** Gets a string that describes the type of this data flow source. */
    abstract string describe();
  }

  /**
   * A data flow sink for cleartext logging of sensitive information.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for cleartext logging of sensitive information.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * A call to `.sub!()` or `.gsub!()` that seems to mask sensitive information.
   */
  private class MaskingReplacer extends Sanitizer, DataFlow::CallNode {
    MaskingReplacer() {
      exists(RegExpLiteral re |
        re = this.getArgument(0).asExpr().getExpr() and
        (
          this.getMethodName() = "sub!" and re.getValueText().matches([".*", ".+"])
          or
          this.getMethodName() = "gsub!" and re.getValueText().matches(".")
        )
      )
    }
  }

  /**
   * A data flow node that does not contain a clear-text password, according to its syntactic name.
   */
  private class NameGuidedNonCleartextPassword extends NonCleartextPassword {
    NameGuidedNonCleartextPassword() {
      exists(string name | name.regexpMatch(notSensitiveRegexp()) |
        this.asExpr().getExpr().(VariableReadAccess).getVariable().getName() = name
        or
        this.asExpr().getExpr().(ElementReference).getArgument(0).getValueText() = name
        or
        this.(DataFlow::CallNode).getMethodName() = name
      )
      or
      // avoid i18n strings
      this.asExpr()
          .getExpr()
          .(ElementReference)
          .getReceiver()
          .getValueText()
          .regexpMatch("(?is).*(messages|strings).*")
    }
  }

  /**
   * A data flow node that receives flow that is not a clear-text password.
   */
  private class NonCleartextPasswordFlow extends NonCleartextPassword {
    NonCleartextPasswordFlow() {
      any(NonCleartextPassword other).(DataFlow::LocalSourceNode).flowsTo(this)
    }
  }

  /**
   * A call that might obfuscate a password, for example through hashing.
   */
  private class ObfuscatorCall extends Sanitizer, DataFlow::CallNode {
    ObfuscatorCall() { this.getMethodName().regexpMatch(notSensitiveRegexp()) }
  }

  /**
   * A data flow node that does not contain a clear-text password.
   */
  abstract private class NonCleartextPassword extends DataFlow::Node { }

  // `writeNode` assigns pair with key `name` to `val`
  private predicate hashKeyWrite(DataFlow::Node writeNode, string name, DataFlow::Node val) {
    exists(SetterMethodCall setter |
      setter = writeNode.asExpr().getExpr() and
      // hash[name]
      setter.getArgument(0).getValueText() = name and
      // val
      setter.getArgument(1).(Assignment).getRightOperand() = val.asExpr().getExpr()
    )
  }

  /**
   * An hash with a value that may contain password information
   *
   * This is a source since logging a hash will show the pairs present.
   */
  private class HashPasswordKeySource extends Source {
    string name;

    HashPasswordKeySource() {
      exists(DataFlow::Node val |
        name.regexpMatch(maybePassword()) and
        not name.regexpMatch(notSensitiveRegexp()) and
        // avoid safe values assigned to presumably unsafe names
        not val instanceof NonCleartextPassword
        and (
          // hash[name] = val
          hashKeyWrite(this, name, val)
          or
          // hash = { name: val }
          exists(Pair p |
            p = this.asExpr().getExpr().(HashLiteral).getAKeyValuePair() |
            p.getKey().getValueText() = name and
            p.getValue() = val.asExpr().getExpr()
          )
        )
      )
    }

    override string describe() { result = "an access to " + name }
  }

  /** An access to a variable or hash value that might contain a password. */
  private class ReadPasswordSource extends Source {
    string name;

    ReadPasswordSource() {
      // avoid safe values assigned to presumably unsafe names
      not this instanceof NonCleartextPassword and
      name.regexpMatch(maybePassword()) and
      (
        this.asExpr().getExpr().(VariableReadAccess).getVariable().getName() = name
        or
        exists(ElementReference ref |
          this.asExpr().getExpr() = ref and
          ref.getArgument(0).getValueText() = name and
          // avoid safe values assigned to presumably unsafe names
          exists(DataFlow::LocalSourceNode write, DataFlow::Node val | localTaint(write, this) |
            hashKeyWrite(write, name, val) and
            not val instanceof NonCleartextPassword
          )
        )
      )
    }

    override string describe() { result = "an access to " + name }
  }

  /** A call that might return a password. */
  private class CallPasswordSource extends DataFlow::CallNode, Source {
    string name;

    CallPasswordSource() {
      name = this.getMethodName() and
      name.regexpMatch("(?is)getPassword")
    }

    override string describe() { result = "a call to " + name }
  }

  private string commonLogMethodName() {
    result = ["info", "debug", "warn", "warning", "error", "log"]
  }

  /**
   * A node representing an expression whose value is logged.
   */
  private class LoggingInputAsSink extends Sink {
    LoggingInputAsSink() {
      // precise match based on inferred type of receiver
      exists(Logging logging | this = logging.getAnInput()) or
      // imprecise name based match
      exists(DataFlow::CallNode call, string recvName |
        recvName = call.getReceiver().asExpr().getExpr().(VariableReadAccess).getVariable().getName() and
        recvName.regexpMatch(".*log(ger)?") and
        call.getMethodName() = commonLogMethodName() |
        this = call.getArgument(_)
      )
    }
  }
}
