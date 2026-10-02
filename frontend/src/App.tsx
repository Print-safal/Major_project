import { useRef, useState } from "react";
import "./App.css";

interface Vulnerability {
  cwe: string;
  vulnerability_name: string;
  location: string;
  explanation: string;
  remediation: string;
}

interface Review {
  vulnerable: boolean;
  vulnerabilities: Vulnerability[];
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
                        </article>
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