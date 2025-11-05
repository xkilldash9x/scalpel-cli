import React, { useState, useEffect } from 'react';

interface GlitchHeaderProps {
  text: string;
}

// Implements the randomized subtle glitch ("binary wall crumbling")
export const GlitchHeader: React.FC<GlitchHeaderProps> = ({ text }) => {
  const [isGlitching, setIsGlitching] = useState(false);

  useEffect(() => {
    let glitchTimeout: ReturnType<typeof setTimeout> | undefined;

    const triggerGlitch = () => {
      setIsGlitching(true);
      // Duration of the glitch effect (matches Tailwind animation duration: 0.5s)
      glitchTimeout = setTimeout(() => setIsGlitching(false), 500);
    };

    // Trigger randomly between 5s and 15s
    const randomInterval = Math.random() * 10000 + 5000;
    const interval = setInterval(triggerGlitch, randomInterval);

    return () => {
      clearInterval(interval);
      if (glitchTimeout) clearTimeout(glitchTimeout);
    };
  }, []);

  // Apply the Tailwind animation class when glitching
  const glitchClass = isGlitching ? 'animate-glitch-short text-cyber-cyan' : 'text-cyber-cyan';

  return (
    <h1 className={`text-xl font-sans font-bold tracking-wider uppercase transition-colors duration-150 ${glitchClass}`}>
      {text}
    </h1>
  );
};