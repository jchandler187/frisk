/**
 * ClawSec v2 - SVG Badge Generator
 */

function generateBadge(verdict) {
    const configs = {
        pass: {
            label: 'clawsec',
            value: 'verified',
            labelColor: '#333',
            valueColor: '#2ea043',
            valueBorderColor: '#2ea04366'
        },
        warn: {
            label: 'clawsec',
            value: 'warnings',
            labelColor: '#333',
            valueColor: '#d29922',
            valueBorderColor: '#d2992266'
        },
        fail: {
            label: 'clawsec',
            value: 'failed',
            labelColor: '#333',
            valueColor: '#da3633',
            valueBorderColor: '#da363366'
        },
        unknown: {
            label: 'clawsec',
            value: 'unknown',
            labelColor: '#333',
            valueColor: '#6e7781',
            valueBorderColor: '#6e778166'
        }
    };

    const config = configs[verdict] || configs.unknown;
    const labelWidth = 62;
    const valueWidth = config.value.length * 7.5 + 16;
    const totalWidth = labelWidth + valueWidth;
    const height = 20;
    const rx = 3;

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${height}" viewBox="0 0 ${totalWidth} ${height}">
  <clipPath id="round">
    <rect width="${totalWidth}" height="${height}" rx="${rx}" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="${labelWidth}" height="${height}" fill="${config.labelColor}"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="${height}" fill="${config.valueColor}"/>
  </g>
  <rect width="${totalWidth}" height="${height}" rx="${rx}" fill="none" stroke="${config.valueBorderColor}" stroke-width="0.5"/>
  <g fill="#fff" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" font-size="11" font-weight="600">
    <text x="${labelWidth / 2}" y="14.5" text-anchor="middle">${config.label}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14.5" text-anchor="middle">${config.value}</text>
  </g>
</svg>`;
}

module.exports = { generateBadge };