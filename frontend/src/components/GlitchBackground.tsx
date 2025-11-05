import React from 'react';

// Background effects: Faint grid lines and ambient glows
export const GlitchBackground: React.FC = () => {
    return (
        <div className="absolute inset-0 z-0 pointer-events-none" aria-hidden="true">
            {/* Faint grid lines */}
            <div className="absolute inset-0 bg-repeat opacity-70" style={{
                backgroundImage: `linear-gradient(to right, rgba(0, 255, 234, 0.05) 1px, transparent 1px),
                                  linear-gradient(to bottom, rgba(0, 255, 234, 0.05) 1px, transparent 1px)`,
                backgroundSize: '80px 80px'
            }} />

            {/* Subtle ambient moving glow/flicker effects */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-cyan/10 rounded-full filter blur-3xl opacity-50 animate-pulse" />
            <div className="absolute bottom-1/4 right-1/4 w-72 h-72 bg-deep-blue/20 rounded-full filter blur-3xl opacity-60 animate-flicker" />
        </div>
    );
};