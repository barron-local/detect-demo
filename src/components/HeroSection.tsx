import React from "react";
import { Sparkles } from "lucide-react";

interface HeroSectionProps {
  totalTools: number;
  filteredCount: number;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  totalTools,
  filteredCount,
}) => {
  return (
    <section className="hero-section">
      <div className="hero-badge">
        <Sparkles size={13} className="hero-badge-icon" />
        <span>Native Forensic Engine</span>
      </div>

      <h1 className="hero-title">
        Forensic <span className="gradient-text">Artifact Suite</span>
      </h1>

      <p className="hero-subtitle">
        {totalTools} standalone security inspection modules for memory, registry, NTFS, and execution history.
        {filteredCount !== totalTools && ` (${filteredCount} matching)`}
      </p>
    </section>
  );
};
