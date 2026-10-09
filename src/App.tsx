import { useState, useMemo, useEffect } from "react";
import { TOOLS_DATA, ToolCategory, ForensicTool } from "./data/toolsData";
import { Navbar } from "./components/Navbar";
import { HeroSection } from "./components/HeroSection";
import { CategoryFilter } from "./components/CategoryFilter";
import { Toolbar } from "./components/Toolbar";
import { ToolCard } from "./components/ToolCard";
import { ToolDetailModal } from "./components/ToolDetailModal";
import { SearchX } from "lucide-react";
import { openExternalLink } from "./utils/openUrl";
import "./App.css";

export function App() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<ToolCategory>("All");
  const [activeFeatureFilter, setActiveFeatureFilter] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"name" | "category" | "badge">("name");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [selectedTool, setSelectedTool] = useState<ForensicTool | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault();
        const input = document.querySelector<HTMLInputElement>(".nav-search-input");
        input?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const filteredTools = useMemo(() => {
    let result = [...TOOLS_DATA];

    if (selectedCategory !== "All") {
      result = result.filter((tool) => tool.category === selectedCategory);
    }

    if (activeFeatureFilter) {
      const q = activeFeatureFilter.toLowerCase();
      result = result.filter(
        (tool) =>
          tool.highlights.some((h) => h.toLowerCase().includes(q)) ||
          tool.features.some((f) => f.toLowerCase().includes(q)) ||
          tool.description.toLowerCase().includes(q)
      );
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      result = result.filter((tool) => {
        return (
          tool.name.toLowerCase().includes(query) ||
          tool.tagline.toLowerCase().includes(query) ||
          tool.description.toLowerCase().includes(query) ||
          tool.category.toLowerCase().includes(query) ||
          tool.targetArtifact.toLowerCase().includes(query) ||
          tool.highlights.some((h) => h.toLowerCase().includes(query)) ||
          tool.features.some((f) => f.toLowerCase().includes(query))
        );
      });
    }

    result.sort((a, b) => {
      if (sortBy === "badge") {
        const priority: Record<string, number> = {
          Featured: 4,
          Core: 3,
          Updated: 2,
          New: 1,
        };
        const pA = a.badge ? priority[a.badge] || 0 : 0;
        const pB = b.badge ? priority[b.badge] || 0 : 0;
        if (pA !== pB) return pB - pA;
      }
      if (sortBy === "category") {
        const catCompare = a.category.localeCompare(b.category);
        if (catCompare !== 0) return catCompare;
      }
      return a.name.localeCompare(b.name);
    });

    return result;
  }, [searchQuery, selectedCategory, activeFeatureFilter, sortBy]);

  const handleResetFilters = () => {
    setSearchQuery("");
    setSelectedCategory("All");
    setActiveFeatureFilter(null);
  };

  return (
    <div className="app-layout">
      <Navbar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        toolCount={TOOLS_DATA.length}
      />

      <main className="main-content">
        <HeroSection
          totalTools={TOOLS_DATA.length}
          filteredCount={filteredTools.length}
        />

        <CategoryFilter
          selectedCategory={selectedCategory}
          onSelectCategory={setSelectedCategory}
        />

        <Toolbar
          sortBy={sortBy}
          onSortChange={setSortBy}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          activeFeatureFilter={activeFeatureFilter}
          onFeatureFilterChange={setActiveFeatureFilter}
          totalFiltered={filteredTools.length}
        />

        {filteredTools.length > 0 ? (
          <div className={`tools-grid ${viewMode === "list" ? "list-view" : ""}`}>
            {filteredTools.map((tool) => (
              <ToolCard
                key={tool.id}
                tool={tool}
                onSelect={setSelectedTool}
              />
            ))}
          </div>
        ) : (
          <div className="empty-state-box">
            <div className="empty-state-icon">
              <SearchX size={28} />
            </div>
            <h3 className="empty-state-title">No matching forensic tools found</h3>
            <p className="empty-state-text">
              We couldn't find any tool matching "<strong>{searchQuery || activeFeatureFilter}</strong>".
              Try adjusting your search terms or category filters.
            </p>
            <button className="btn-reset-filters" onClick={handleResetFilters}>
              Clear All Filters
            </button>
          </div>
        )}
      </main>

      <ToolDetailModal
        tool={selectedTool}
        onClose={() => setSelectedTool(null)}
      />

      <footer className="site-footer">
        <div className="footer-content">
          <div>
            <span>© 2026 DETECT.AC — Built with Tauri & React for PC Checkers & Forensic Analysts.</span>
          </div>
          <div className="footer-links">
            <button
              className="footer-link btn-link-plain"
              onClick={() => openExternalLink("https://detect.ac")}
            >
              detect.ac Official
            </button>
            <button
              className="footer-link btn-link-plain"
              onClick={() => openExternalLink("https://detect.ac/tools")}
            >
              All Tools Catalog
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
