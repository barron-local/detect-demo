import React from "react";
import { ShieldCheck, Cpu, Terminal, Zap, Sparkles } from "lucide-react";

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
        <Sparkles size={14} className="hero-badge-icon" />
        <span>Official detect.ac Forensic Ecosystem</span>
      </div>

      <h1 className="hero-title">
        Included Tools & <span className="gradient-text">Forensic Arsenal</span>
      </h1>

      <p className="hero-subtitle">
        A comprehensive collection of {totalTools} enhanced forensic analysis tools, memory dumpers,
        USN journal trackers, and anti-cheat integrity scanners engineered for investigators
        and PC Checkers. (Showing {filteredCount} tools)
      </p>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-icon-wrap">
            <Zap size={18} className="metric-icon text-cyan" />
          </div>
          <div className="metric-data">
            <span className="metric-value">{totalTools}</span>
            <span className="metric-label">Enhanced Tools</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <ShieldCheck size={18} className="metric-icon text-emerald" />
          </div>
          <div className="metric-data">
            <span className="metric-value">12+</span>
            <span className="metric-label">YARA / USN Engines</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <Cpu size={18} className="metric-icon text-purple" />
          </div>
          <div className="metric-data">
            <span className="metric-value">Dual-Mode</span>
            <span className="metric-label">Kernel & User RAM</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <Terminal size={18} className="metric-icon text-amber" />
          </div>
          <div className="metric-data">
            <span className="metric-value">100%</span>
            <span className="metric-label">Local & Anti-Bypass</span>
          </div>
        </div>
      </div>
    </section>
  );
};
