import React from "react";
import { ToolCategory, CATEGORIES, TOOLS_DATA } from "../data/toolsData";
import {
  LayoutGrid,
  History,
  HardDrive,
  Cpu,
  Zap,
  Usb,
  Globe,
  Terminal,
  ShieldCheck,
  LucideProps,
} from "lucide-react";

interface CategoryFilterProps {
  selectedCategory: ToolCategory;
  onSelectCategory: (cat: ToolCategory) => void;
}

const iconMap: Record<string, React.FC<LucideProps>> = {
  LayoutGrid,
  History,
  HardDrive,
  Cpu,
  Zap,
  Usb,
  Globe,
  Terminal,
  ShieldCheck,
};

export const CategoryFilter: React.FC<CategoryFilterProps> = ({
  selectedCategory,
  onSelectCategory,
}) => {
  const getCategoryCount = (cat: ToolCategory) => {
    if (cat === "All") return TOOLS_DATA.length;
    return TOOLS_DATA.filter((t) => t.category === cat).length;
  };

  return (
    <div className="category-filter-bar">
      <div className="category-scroll-container">
        {CATEGORIES.map((item) => {
          const IconComp = iconMap[item.icon] || LayoutGrid;
          const isSelected = selectedCategory === item.label;
          const count = getCategoryCount(item.label);

          return (
            <button
              key={item.label}
              className={`category-pill ${isSelected ? "active" : ""}`}
              onClick={() => onSelectCategory(item.label)}
            >
              <IconComp size={15} className="category-icon" />
              <span className="category-name">{item.label}</span>
              <span className="category-badge-count">{count}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
