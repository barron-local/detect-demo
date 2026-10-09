import React from "react";
import {
  Zap,
  Binary,
  ShieldCheck,
  FileClock,
  Usb,
  FolderSearch,
  Terminal,
  FolderGit2,
  HardDrive,
  Cpu,
  Activity,
  AlertTriangle,
  Globe,
  DownloadCloud,
  Clock,
  ShieldAlert,
  Network,
  HelpCircle,
  LucideProps,
} from "lucide-react";

interface ToolIconProps extends LucideProps {
  name: string;
}

const iconMap: Record<string, React.FC<LucideProps>> = {
  Zap,
  Binary,
  ShieldCheck,
  FileClock,
  Usb,
  FolderSearch,
  Terminal,
  FolderGit2,
  HardDrive,
  Cpu,
  Activity,
  AlertTriangle,
  Globe,
  DownloadCloud,
  Clock,
  ShieldAlert,
  Network,
};

export const ToolIcon: React.FC<ToolIconProps> = ({ name, ...props }) => {
  const IconComponent = iconMap[name] || HelpCircle;
  return <IconComponent {...props} />;
};
