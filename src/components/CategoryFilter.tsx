import React, { useRef, useState, useEffect } from "react";
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
  ChevronLeft,
  ChevronRight,
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
  const scrollRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const [scrollLeftState, setScrollLeftState] = useState(0);

  const getCategoryCount = (cat: ToolCategory) => {
    if (cat === "All") return TOOLS_DATA.length;
    return TOOLS_DATA.filter((t) => t.category === cat).length;
  };

  const checkScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    setCanScrollLeft(el.scrollLeft > 5);
    setCanScrollRight(el.scrollLeft < el.scrollWidth - el.clientWidth - 5);
  };

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    checkScroll();
    window.addEventListener("resize", checkScroll);

    const handleWheel = (e: WheelEvent) => {
      if (e.deltaY !== 0) {
        e.preventDefault();
        el.scrollLeft += e.deltaY;
        checkScroll();
      }
    };

    el.addEventListener("wheel", handleWheel, { passive: false });

    return () => {
      window.removeEventListener("resize", checkScroll);
      el.removeEventListener("wheel", handleWheel);
    };
  }, []);

  const handleScrollBy = (offset: number) => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollBy({ left: offset, behavior: "smooth" });
    setTimeout(checkScroll, 300);
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const el = scrollRef.current;
    if (!el) return;
    setIsDragging(true);
    setStartX(e.pageX - el.offsetLeft);
    setScrollLeftState(el.scrollLeft);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    const el = scrollRef.current;
    if (!el) return;
    e.preventDefault();
    const x = e.pageX - el.offsetLeft;
    const walk = (x - startX) * 1.5;
    el.scrollLeft = scrollLeftState - walk;
    checkScroll();
  };

  const handleMouseUpOrLeave = () => {
    setIsDragging(false);
  };

  return (
    <div className="category-filter-bar">
      {canScrollLeft && (
        <button
          type="button"
          className="category-nav-btn category-nav-prev"
          onClick={() => handleScrollBy(-220)}
          aria-label="Scroll left"
        >
          <ChevronLeft size={15} />
        </button>
      )}

      <div
        ref={scrollRef}
        className={`category-scroll-container ${isDragging ? "dragging" : ""}`}
        onScroll={checkScroll}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUpOrLeave}
        onMouseLeave={handleMouseUpOrLeave}
      >
        {CATEGORIES.map((item) => {
          const IconComp = iconMap[item.icon] || LayoutGrid;
          const isSelected = selectedCategory === item.label;
          const count = getCategoryCount(item.label);

          return (
            <button
              key={item.label}
              type="button"
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

      {canScrollRight && (
        <button
          type="button"
          className="category-nav-btn category-nav-next"
          onClick={() => handleScrollBy(220)}
          aria-label="Scroll right"
        >
          <ChevronRight size={15} />
        </button>
      )}
    </div>
  );
};
