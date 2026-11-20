import { useRef, useState } from "react";
import "./App.css";

type ConfidenceLevel = "High" | "Medium" | "Low" | "Undetermined";

interface SourceLocation {
  line_start: number;
  column_start: number;
  line_end: number;
  column_end: number;
}

interface EvidenceReference {
  cwe_id: string;
  kind: "semantic" | "vulnerable" | "secure" | "contextual";
  evidence: string;
  provenance: string;
  score?: number | null;
  location?: SourceLocation | null;
  explanation: string;
}

interface ConfidenceComponent {
  name: string;
  score: number | null;
  level: ConfidenceLevel;
  weight: number;
  explanation: string;
  supporting_evidence?: EvidenceReference[];
  conflicting_evidence?: EvidenceReference[];
}

interface FindingConfidence {
  cwe_id: string;
  location: string;
  score: number | null;
  level: ConfidenceLevel;
  components?: ConfidenceComponent[];
  supporting_evidence?: EvidenceReference[];
  conflicting_evidence?: EvidenceReference[];
  explanation?: string;
}

interface AssessmentConfidence {
  vulnerable: boolean;
  score: number | null;
  level: ConfidenceLevel;
  components?: ConfidenceComponent[];
  finding_confidences?: FindingConfidence[];
  supporting_evidence?: EvidenceReference[];
  conflicting_evidence?: EvidenceReference[];
  explanation?: string;
}

interface Vulnerability {
  cwe: string;
  vulnerability_name: string;
  location: string;
  explanation: string;
  remediation: string;
  confidence?: FindingConfidence | null;
}

interface Review {
  vulnerable: boolean;
  vulnerabilities: Vulnerability[];
  assessment_confidence?: AssessmentConfidence | null;
}

interface AnalysisResponse {
  filename: string;
  language: string;
  review: Review;
}

function App() {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [dragging, setDragging] = useState(false);

  const confidenceClass = (level?: ConfidenceLevel) =>
    `confidence-${(level ?? "Undetermined").toLowerCase()}`;

  const renderEvidence = (items?: EvidenceReference[]) => {
    if (!items?.length) return <p className="evidence-empty">None provided.</p>;
    return (
      <ul className="evidence-list">
        {items.map((item, index) => (
          <li key={`${item.cwe_id}-${item.kind}-${index}`}>
            <span className="evidence-kind">{item.kind}</span>
            <p>{item.explanation || item.evidence}</p>
            {item.location && (
              <span className="evidence-location">
                Lines {item.location.line_start}–{item.location.line_end}
              </span>
            )}
          </li>
        ))}
      </ul>
    );
  };

  const renderConfidence = (confidence?: FindingConfidence | AssessmentConfidence | null) => {
    if (!confidence) return null;
    const level = confidence?.level ?? "Undetermined";
    const score = confidence?.score;
    return (
      <div className={`confidence-block ${confidenceClass(level)}`}>
        <div className="confidence-summary">
          <span className="result-label">Confidence</span>
          <span className="confidence-pill">{level}</span>
          {score != null && <strong>{Math.round(score)}/100</strong>}
        </div>
        {score != null && (
          <progress
            className="confidence-progress"
            value={score}
            max={100}
            aria-label={`${level} confidence: ${Math.round(score)} out of 100`}
          />
        )}
        {confidence?.explanation && <p className="confidence-explanation">{confidence.explanation}</p>}
      </div>
    );
  };

  const selectFile = (file: File) => {
    setError("");
    setResult(null);

    if (!file.name.toLowerCase().endsWith(".py")) {
      setSelectedFile(null);
      setError("Only Python (.py) files are allowed.");
      return;
    }

    setSelectedFile(file);
  };

  const handleBrowse = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];

    if (file) {
      selectFile(file);
    }
  };

  const handleDrop = (
    event: React.DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    setDragging(false);

    const file = event.dataTransfer.files?.[0];

    if (file) {
      selectFile(file);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError("Please select a Python file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("/api/analyze/", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed.");
      }

      setResult(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong while analyzing the file."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleNewReview = () => {
    setSelectedFile(null);
    setResult(null);
    setError("");
    setLoading(false);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="navbar">
        <div className="brand">
          <div className="brand-icon">{"</>"}</div>

          <div>
            <h1>AI Code Reviewer</h1>
            <p>Intelligent Python security analysis</p>
          </div>
        </div>

        <div className="status">
          <span className="status-dot" />
          System ready
        </div>
      </header>

      <main className="main-content">
        {/* Hero */}
        <section className="hero">
          <div className="badge">
            AI-POWERED SECURITY REVIEW
          </div>

          <h2>
            Find security vulnerabilities
            <span> before they reach production.</span>
          </h2>

          <p>
            Upload your Python source code and let our RAG + LLM
            pipeline analyze it for common security vulnerabilities.
          </p>
        </section>

        {/* Main workspace */}
        <section className="review-card">
          {/* Upload panel */}
          <div className="upload-area">
            <div
              className={`drop-zone ${dragging ? "dragging" : ""}`}
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              onClick={handleBrowse}
            >
              <div className="upload-icon">
                ↑
              </div>

              <h3>
                {selectedFile
                  ? "Python file selected"
                  : "Upload Python code"}
              </h3>

              <p>
                {selectedFile ? (
                  <>
                    Ready to analyze your
                    <br />
                    <strong>{selectedFile.name}</strong>
                  </>
                ) : (
                  <>
                    Drag and drop your <strong>.py</strong> file
                    <br />
                    or browse from your computer
                  </>
                )}
              </p>

              <input
                ref={fileInputRef}
                type="file"
                accept=".py"
                onChange={handleFileChange}
                hidden
              />

              <button
                className="browse-button"
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  handleBrowse();
                }}
                disabled={loading}
              >
                {selectedFile ? "Change file" : "Browse file"}
              </button>

              <span className="file-hint">
                Python files only
              </span>
            </div>

            {selectedFile && (
              <div className="selected-file">
                <span className="file-icon">PY</span>

                <div className="file-info">
                  <strong>{selectedFile.name}</strong>
                  <span>
                    {(selectedFile.size / 1024).toFixed(1)} KB
                  </span>
                </div>
              </div>
            )}

            <button
              className="analyze-button"
              type="button"
              onClick={handleAnalyze}
              disabled={!selectedFile || loading}
            >
              {loading ? (
                <>
                  <span className="button-spinner" />
                  Analyzing...
                </>
              ) : (
                "Analyze Code"
              )}
            </button>

            {result && (
              <button
                className="new-review-button"
                type="button"
                onClick={handleNewReview}
              >
                + New Review
              </button>
            )}

            {error && (
              <div className="error-message">
                {error}
              </div>
            )}
          </div>

          {/* Results panel */}
          <div className="results-area">
            {!result && !loading && (
              <div className="empty-state">
                <div className="placeholder-icon">
                  ✓
                </div>

                <h3>Security results</h3>

                <p>
                  Your vulnerability analysis will appear here
                  after submitting a Python file.
                </p>

                <div className="supported-cwes">
                  <span>CWE-22</span>
                  <span>CWE-78</span>
                  <span>CWE-79</span>
                  <span>CWE-89</span>
                  <span>CWE-798</span>
                </div>
              </div>
            )}

            {loading && (
              <div className="loading-state">
                <div className="loading-spinner" />

                <h3>Analyzing your code</h3>

                <p>
                  Retrieving security evidence and performing
                  AI-assisted review.
                </p>

                <span className="loading-note">
                  This may take a few seconds
                </span>
              </div>
            )}

            {result && (
              <div className="results-content">
                <div className="results-header">
                  <div>
                    <div
                      className={`result-status ${
                        result.review.vulnerable
                          ? "danger"
                          : "safe"
                      }`}
                    >
                      <span>
                        {result.review.vulnerable ? "!" : "✓"}
                      </span>

                      {result.review.vulnerable
                        ? "Vulnerabilities detected"
                        : "No vulnerabilities detected"}
                    </div>

                    <div className="result-file">
                      {result.filename}
                    </div>
                  </div>

                  {result.review.vulnerabilities.length > 0 && (
                    <div className="vulnerability-count">
                      {result.review.vulnerabilities.length}
                      <span>
                        {result.review.vulnerabilities.length === 1
                          ? " issue"
                          : " issues"}
                      </span>
                    </div>
                  )}
                </div>

                {renderConfidence(result.review.assessment_confidence)}
                {result.review.assessment_confidence && (
                  <details className="assessment-evidence">
                    <summary>Assessment evidence</summary>
                    <p className="evidence-explanation">
                      {result.review.assessment_confidence.explanation || "No additional assessment explanation was provided."}
                    </p>
                    {result.review.assessment_confidence.components?.length ? (
                      <div className="component-list">
                        <h5>Confidence components</h5>
                        {result.review.assessment_confidence.components.map((component) => (
                          <div className="component-item" key={component.name}>
                            <div className="component-heading">
                              <strong>{component.name}</strong>
                              <span className={`confidence-pill ${confidenceClass(component.level)}`}>
                                {component.level}{component.score != null ? ` · ${Math.round(component.score)}/100` : ""}
                              </span>
                            </div>
                            <p>{component.explanation}</p>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="evidence-columns">
                      <section>
                        <h5>Supporting evidence</h5>
                        {renderEvidence(result.review.assessment_confidence.supporting_evidence)}
                      </section>
                      <section>
                        <h5>Conflicting evidence</h5>
                        {renderEvidence(result.review.assessment_confidence.conflicting_evidence)}
                      </section>
                    </div>
                  </details>
                )}

                {result.review.vulnerabilities.length === 0 && (
                  <div className="safe-result">
                    <div className="safe-icon">✓</div>

                    <h3>Code looks safe</h3>

                    <p>
                      The security review did not identify any
                      supported vulnerabilities in this file.
                    </p>
                  </div>
                )}

                {result.review.vulnerabilities.length > 0 && (
                  <div className="vulnerability-list">
                    {result.review.vulnerabilities.map(
                      (vulnerability, index) => (
                        (() => {
                          const findingConfidence = vulnerability.confidence ??
                            result.review.assessment_confidence?.finding_confidences?.[index];
                          return (
                        <article
                          className="vulnerability-card"
                          key={`${vulnerability.cwe}-${index}`}
                        >
                          <div className="vulnerability-header">
                            <span className="cwe-badge">
                              {vulnerability.cwe}
                            </span>

                            <h4>
                              {vulnerability.vulnerability_name}
                            </h4>
                          </div>

                          {renderConfidence(findingConfidence)}

                          <div className="result-section">
                            <span className="result-label">
                              Location
                            </span>

                            <p>
                              {vulnerability.location}
                            </p>
                          </div>

                          <div className="result-section">
                            <span className="result-label">
                              Explanation
                            </span>

                            <p>
                              {vulnerability.explanation}
                            </p>
                          </div>

                          <div className="result-section remediation">
                            <span className="result-label">
                              Remediation
                            </span>

                            <p>
                              {vulnerability.remediation}
                            </p>
                          </div>

                          <details className="evidence-details">
                            <summary>Evidence and confidence details</summary>
                            <p className="evidence-explanation">
                              {findingConfidence?.explanation || "No additional confidence explanation was provided."}
                            </p>
                            {findingConfidence?.components?.length ? (
                              <div className="component-list">
                                <h5>Confidence components</h5>
                                {findingConfidence.components.map((component) => (
                                  <div className="component-item" key={component.name}>
                                    <div className="component-heading">
                                      <strong>{component.name}</strong>
                                      <span className={`confidence-pill ${confidenceClass(component.level)}`}>
                                        {component.level}{component.score != null ? ` · ${Math.round(component.score)}/100` : ""}
                                      </span>
                                    </div>
                                    <p>{component.explanation}</p>
                                  </div>
                                ))}
                              </div>
                            ) : null}
                            <div className="evidence-columns">
                              <section>
                                <h5>Supporting evidence</h5>
                                {renderEvidence(findingConfidence?.supporting_evidence)}
                              </section>
                              <section>
                                <h5>Conflicting evidence</h5>
                                {renderEvidence(findingConfidence?.conflicting_evidence)}
                              </section>
                            </div>
                          </details>
                        </article>
                          );
                        })()
                      )
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </main>

      <footer>
        <span>AI Code Reviewer</span>
        <span>RAG + LLM Security Analysis</span>
      </footer>
    </div>
  );
}

export default App;
